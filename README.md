# Windows Transparent & Forward Proxy Gateway (tproxy)

> ### 🌐 Windows は設定ゼロの完全透過制御。WSL は簡単プロキシ設定で一括制御。
> **ブラウザ・CLI・SSH・RDP、そして WSL（Linux）まで——PC 上の全通信を安全に制御・監査・中継する多機能プロキシゲートウェイ。**

---

## 💡 本ツールの設計コンセプト（ハイブリッドプロキシへの進化）

`tproxy` は元々、OS やアプリにプロキシ設定を一切行わずに通信を横取りする「完全透過プロキシ」として誕生しました。  
しかし、社内 NTLM/SSO 認証、PAC スクリプト自動解決、DNS-over-HTTPS (DoH)、L7 プロトコル自動識別、RDP/SSH 常時接続維持、そして **WSL2（Windows Subsystem for Linux）の通信制御** といった実用上の要件を取り込む中で、**「透過型プロキシ」と「明示的フォワードプロキシ（HTTP CONNECT）」が完全共存する多機能プロキシゲートウェイ** へと進化しました。

### 📌 Windows と WSL2 の制御方式の違い

| 対象環境 | 制御方式 | 設定方法 | 動作の仕組み |
| :--- | :--- | :--- | :--- |
| **Windows ホスト側**<br>(ブラウザ、SSH、RDP、CLI等) | **完全透過プロキシ**<br>(Transparent) | **設定一切不要**<br>(OS/アプリ設定 0) | WinDivert によりカーネル層（WFP）でパケットを自動横取りしてローカル中継 |
| **WSL2 (Linux 側)**<br>(Ubuntu、Docker、curl、apt等) | **明示的プロキシ**<br>(Explicit Forward) | **環境変数 1 行**<br>(`export https_proxy=...`) | Windows ホストの `127.0.0.1:18080` へプロキシ指定することで確実に制御 |

---

### ⚠️ なぜ WSL2 は「透過プロキシ」ができないのか？（技術的制約と解決策）

以前は「WSL も自動的に透過制御される」と期待されていましたが、技術検証の結果、以下の構造的理由により **WSL2 の通信を Windows ホスト側から透過的に横取りすることは原理的に不可能** であることが判明しました：

1. **Hyper-V 仮想スイッチ（NDIS Layer 2）によるバイパス**:  
   WSL2 の仮想マシンが送信するパケットは、Windows ホストのパケットフィルタ層（WFP / WinDivert）よりも下層にある **Hyper-V vSwitch（Layer 2）** を通じて直接物理アダプタへ送出されます。
2. **WinDivert のフックポイントを通過しない**:  
   WinDivert の Layer 0（ネットワーク層）および Layer 1（IPフォワード層）のいずれを有効化しても、仮想マシンのパケットはホストの WFP スタックを通過しないため、ホスト側で透過的にキャッチすることができません。

#### ✅ `tproxy` の解決策：ハイブリッドフォールバック
WSL2 の通信を確実に制御・監査するため、`tproxy` のローカルリスナー（`18080`）に **「明示的 HTTP/HTTPS CONNECT プロキシ機能」** を統合しました。  
WSL 側から `http://127.0.0.1:18080` をプロキシとして指定するだけで、**Windows ホスト側の透過制御と全く同一のポリシー（ホワイトリスト/ブラックリスト、DoH、社内プロキシ中継、ログ監査）が WSL からの通信にも 100% 適用** されます。

> 🔒 **自端末 & WSL 限定のアクセス制限（オープンプロキシ化防止）**  
> ポート `18080` への明示的プロキシ要求は、接続元 IP が **自端末（`127.0.0.1` / `::1`）または WSL 仮想サブネットであるかを厳格に自動検証** します。同一 LAN 内の他端末や外部からのアクセスはすべて `403 Forbidden` で即座に遮断されるため、踏み台（オープンプロキシ）として悪用されるセキュリティリスクはありません。

---

## 🚀 多機能化された核心機能一覧

| 分類 | 機能 | メリット・詳細 |
|:---:|:---|:---|
| **透過制御** | 🌐 **Windows ゼロ設定の透過制御** | Windows 側はブラウザや CLI のプロキシ設定なしで全アプリの通信を自動制御 |
| **WSL連携** | 🐧 **WSL2 ハイブリッドプロキシ** | `export https_proxy=http://127.0.0.1:18080` だけで Linux 側の通信も同一ポリシーで一括制御 |
| **セキュリティ** | 🚦 **ホスト & IP フィルタリング** | ホワイトリスト/ブラックリスト、ワイルドカード（`*.example.com`）、CIDR（`10.0.0.0/8`）対応 |
| **プロトコル** | 🧠 **L7 シグネチャ自動判別** | ポート番号に依存せず TLS / HTTP / SSH / RDP / VNC をパケット先頭シグネチャで自動識別 |
| **DNS保護** | 🛡️ **DNS-over-HTTPS (DoH) 昇格** | 平文 DNS（UDP 53）を暗号化 DoH へ自動変換 ＆ 高速インメモリキャッシュ（0ms 応答） |
| **エンタープライズ** | 🏢 **社内プロキシ ＆ Windows SSO** | 社内 NTLM / PAC プロキシへ Windows サインイン資格情報（SSPI）でパスワードレス自動ログイン |
| **セッション維持** | ⏱️ **RDP / SSH 常時接続維持** | リモート操作・ターミナル等の無操作切断を自動防止（`idleTimeout=0` ＆ Keep-Alive） |
| **安全性** | 🔒 **完全ローカル ＆ クラッシュセーフ** | 外部送信なし。終了時はカーネルがパケット横取りを 100% 自動解除して通常通信へ瞬時復帰 |

---

## 1. 🚀 クイックスタート（3ステップで今すぐ使う）

### 📦 事前準備: WinDivert の入手（初回のみ）
本アプリは Windows 上のパケット制御に **WinDivert** を使用します。`WinDivert.dll` と `WinDivert64.sys` を `tproxy.exe` と同じフォルダに配置してください：

1. [WinDivert 公式サイト](https://reqrypt.org/windivert.html) または [GitHub Releases](https://github.com/basil00/Divert/releases) から最新の zip をダウンロード。
2. zip 内の `x64\` フォルダにある **`WinDivert.dll`** と **`WinDivert64.sys`** を `tproxy.exe` と同じフォルダにコピーします。

---

### Step 1: ビルドする
PowerShell またはコマンドプロンプトで以下を実行します：
```powershell
go build -ldflags="-s -w" -o tproxy.exe ./cmd/tproxy
```

### Step 2: 設定ファイル（`config.json`）を確認する
初期状態で開発者向け主要サイト（GitHub, Google, Go, NPM, Python, Docker 等）と Windows Update が許可されています。  
通信を一切遮断せず全通しで試したい場合は、`config.json` を以下のようにするだけでOKです：
```json
{
  "filter_mode": "all"
}
```

### Step 3: 管理者権限で起動する
WinDivert パケットドライバをロードするため、**「管理者として実行」した PowerShell** で起動します：
```powershell
.\tproxy.exe
```

これだけで、Windows PC 上のすべての通信が透過的に保護・制御されます（Windows 側のアプリやブラウザの設定変更は一切不要です）。

### 🛑 停止方法
コンソールで **`Ctrl + C`** を押すと、直ちにパケットの横取りが 100% 自動解除され、OS 標準の通常通信へ瞬時に復元して安全に終了します。

---

## 2. 🐧 WSL2 での使い方（ミラーモード連携）

WSL2 から `tproxy` を経由させるには、WSL のネットワークをミラーモードに設定し、プロキシ環境変数を指定します。

### ① WSL のネットワーク設定 (`%UserProfile%\.wslconfig`)
Windows 側の `%UserProfile%\.wslconfig` に以下を記述します：
```ini
[wsl2]
networkingMode=mirrored
firewall=true
```
※ 設定後、PowerShell で `wsl --shutdown` を実行して WSL を再起動します。

### ② WSL ターミナルでプロキシを設定
WSL 内の `~/.bashrc` またはターミナルで以下を実行します：
```bash
# プロキシ環境変数を設定（ミラーモード時は 127.0.0.1 で Windows ホストの tproxy に直結）
export http_proxy=http://127.0.0.1:18080
export https_proxy=http://127.0.0.1:18080
export all_proxy=http://127.0.0.1:18080

# 動作確認（curl でアクセス）
curl -v https://www.google.com
```

> **💡 単発テスト**: 環境変数を設定せず `curl -v -x http://127.0.0.1:18080 https://www.alpha.co.jp` のように `-x` オプションで直接テストすることも可能です。  
> **💡 永続化**: `~/.bashrc` の末尾に上記 `export` を追記しておくと、WSL 起動時に自動でプロキシが適用されます。

---

## 3. 📖 基本的な使い方・コマンド集

### ① 通常起動（推奨）
主要なアクセスログのみをシンプルに出力します：
```powershell
.\tproxy.exe
```
**ログ出力例:**
```text
# Windows 側の透過通信
[ALLOW] DNS-DoH          | Client: 192.168.1.50:54320 | Target: 1.1.1.2:53                    | Query: github.com (A) -> DoH (15ms)
[ALLOW] HTTPS            | Client: 192.168.1.50:54321 | Target: github.com:443                -> DIRECT

# WSL 側の明示的プロキシ通信
[ALLOW] HTTPS (EXPLICIT) | Client: 127.0.0.1:45530    | Target: www.alpha.co.jp:443            -> DIRECT
[BLOCK] HTTPS (EXPLICIT) | Client: 127.0.0.1:45532    | Target: dangerous-site.com:443        -> Blocked by policy
[CLOSE] Client: 127.0.0.1:45530 | Target: www.alpha.co.jp:443 | Sent: 1.7 KB | Recv: 91.6 KB | Duration: 451ms
```

### ② 詳細ログ付き起動 (`-v` / `-verbose`)
パケットの送受信、NAT書き換え、非同期接続の詳細など、トラブルシューティング用のログを表示します：
```powershell
.\tproxy.exe -v
```

### ③ ドライラン起動 (`-d` / `-dry-run`)
通信を遮断・変更せず、パッシブに監視して「許可/遮断のシミュレーション結果」のみを出力します（本番導入前の監査に最適）：
```powershell
.\tproxy.exe -d
```

### ④ ログファイルへの保存 (`-log` / `-l`)
コンソールへの表示と同時に、指定したファイルへログを出力・保存します（起動ごとにファイルを新規上書きします）：
```powershell
.\tproxy.exe -log log.txt
```
*(短縮形: `.\tproxy.exe -l log.txt`)*

> **💡 ヒント**: `config.json` に `"log_file": "log.txt"` を記述しておくと、引数なしの起動でも自動的にファイルへ保存されます。

### ⑤ 設定ファイルを指定して起動 (`-c`)
```powershell
.\tproxy.exe -c C:\path\to\my_config.json
```

---

## 4. ⚙️ 設定ファイル（`config.json`）の書き方

設定ファイルは **アプリ稼働中に編集・保存しても、再起動不要で即座に自動反映（ホットリロード）** されます。

### 📋 全設定パラメータ一覧（完全リファレンス）

| キー名 | 型 | デフォルト値 | 説明 |
| :--- | :---: | :---: | :--- |
| **`filter_mode`** | `string` | `"whitelist"` | フィルタリングモード。`"whitelist"`（許可リストのみ）、`"blacklist"`（拒否リストのみ）、`"all"` / `"none"`（全通し）から選択。 |
| **`allowed_domains`** | `[]string` | `[]` | ホワイトリスト時に通信を許可するドメイン・ワイルドカード一覧（例: `["*.github.com", "google.com"]`）。 |
| **`allowed_ips`** | `[]string` | `[]` | ホワイトリスト時に通信を許可する IP アドレス / CIDR 一覧（例: `["127.0.0.1", "10.0.0.0/8"]`）。 |
| **`blocked_domains`** | `[]string` | `[]` | ブラックリスト時に通信を遮断するドメイン・ワイルドカード一覧（例: `["*.badsite.com"]`）。 |
| **`blocked_ips`** | `[]string` | `[]` | ブラックリスト時に通信を遮断する IP アドレス / CIDR 一覧（例: `["198.51.100.25", "203.0.113.0/24"]`）。 |
| **`listen_addr`** | `string` | `"0.0.0.0:18080"` | ローカルプロキシサーバーの待受けアドレス（ポート衝突時は自動で別ポートへ退避）。 |
| **`pac_url`** | `string` | `""` | 上位プロキシ自動構成スクリプト（PAC/WPAD）の URL（例: `"http://wpad.corp.local/wpad.dat"`）。 |
| **`upstream_proxy`** | `string` | `""` | 固定上位 HTTP プロキシ URL（例: `"http://proxy.corp.local:8080"`）。 |
| **`bypass_sspi`** | `bool` | `false` | `true` にすると上位プロキシへの Windows 統合認証（SSPI / NTLM / Kerberos）を無効化。 |
| **`doh_enabled`** | `bool` | `true` | 平文 DNS（UDP 53）を DNS-over-HTTPS (DoH) へ自動昇格する機能の有効/無効。 |
| **`doh_timeout_sec`** | `int` | `3` | DoH クエリのタイムアウト秒数。 |
| **`fallback_to_udp`** | `bool` | `true` | DoH 失敗時または非対応の際、平文 UDP 53 へフォールバックするかどうか。 |
| **`dns_cache_enabled`** | `bool` | `true` | インメモリ DNS キャッシュ（2回目以降 0ms 応答）の有効/無効。 |
| **`dns_cache_ttl_sec`** | `int` | `300` | DNS キャッシュの最大保持秒数（TTL）。 |
| **`connect_timeout_sec`**| `int` | `10` | 上流サーバー / 上位プロキシへの TCP 接続タイムアウト秒数。 |
| **`idle_timeout_sec`** | `int` | `120` | アイドル（無通信）接続の切断秒数。`0` にすると無制限維持。 |
| **`reload_interval_sec`**| `int` | `5` | 設定ファイルの変更検知＆ホットリロードの確認周期（秒）。 |
| **`log_file`** | `string` | `""` | ログ出力先のファイルパス（例: `"log.txt"`）。空文字の場合はコンソールのみ。 |
| **`dry_run`** | `bool` | `false` | `true` にすると通信を遮断・変更せず監査ログ出力のみを行うドライランモードで動作。 |
| **`divert_filter`** | `string` | `""` (自動生成) | WinDivert のカスタムキャプチャ条件（※通常は空文字推奨。指定時は `outbound` と `!loopback` を必須付与）。 |

---

### パターン 1: ホワイトリスト形式（おすすめ・セキュア運用）
指定したドメイン・IP 宛てのみを許可し、未知のサイトをすべて自動遮断します（Windows / WSL 双方に共通適用）：
```json
{
  "filter_mode": "whitelist",
  "allowed_domains": [
    "github.com",
    "*.github.com",
    "*.githubusercontent.com",
    "google.com",
    "*.google.com",
    "*.microsoft.com",
    "*.windowsupdate.com"
  ],
  "allowed_ips": [
    "127.0.0.1",
    "::1",
    "192.168.0.0/16",
    "10.0.0.0/8",
    "fe80::/10",
    "2001:db8::/32"
  ]
}
```

### パターン 2: ブラックリスト形式
特定の危険なサイトや SNS のみを遮断し、それ以外をすべて許可します：
```json
{
  "filter_mode": "blacklist",
  "blocked_domains": [
    "*.example-blocked.com",
    "badsite.example.org"
  ],
  "blocked_ips": [
    "198.51.100.25",
    "203.0.113.0/24",
    "2001:db8:evil::/48"
  ]
}
```

### パターン 3: 社内プロキシ・PAC ファイルの指定
```json
{
  "filter_mode": "all",
  "upstream_proxy": "http://proxy.corp.local:8080",
  "pac_url": "http://wpad.corp.local/wpad.dat"
}
```
> **※ 認証について**: 上位プロキシが統合Windows認証（NTLM / SSO）を要求する場合、Windowsのサインイン資格情報を使って自動認証（パスワードレス）されます。

### パターン 4: DNS-over-HTTPS (DoH) とインメモリキャッシュの設定
```json
{
  "doh_enabled": true,
  "doh_timeout_sec": 3,
  "fallback_to_udp": true,
  "dns_cache_enabled": true,
  "dns_cache_ttl_sec": 300
}
```
* **`doh_enabled`**: DNS-to-DoH自動昇格機能の有効/無効（デフォルト: `true`）。
* **`fallback_to_udp`**: 万が一DoH通信に失敗した際、通常の平文UDP 53で再試行して通信遮断を防ぐ（デフォルト: `true`）。
* **`dns_cache_enabled`**: インメモリキャッシュの有効化（デフォルト: `true`）。2回目以降の同一クエリを0msで即座に応答します。
* **`dns_cache_ttl_sec`**: キャッシュの最大保持秒数（デフォルト: `300` = 5分）。レコードのTTLに基づき定期的に自動更新されます。

### パターン 5: タイムアウト設定と大容量・常時接続の挙動
```json
{
  "connect_timeout_sec": 10,
  "idle_timeout_sec": 120
}
```
* **`connect_timeout_sec`**: 相手先サーバーや上位プロキシへの接続タイムアウト秒数（デフォルト: `10`秒）。
* **`idle_timeout_sec`**: アイドル（**無通信**）状態が続いた場合にソケットを安全に解放する秒数（デフォルト: `120`秒）。
  * **💡 大容量ダウンロードへの影響**: この設定は「通信上限時間」ではなく「無通信時間」の監視です。データが流れている間は**パケットを受信するたびに期限が自動延長**されるため、数時間・数十GBに及ぶ巨大ファイルのダウンロードでも**途中で切断されることはありません**。
  * **💡 `0` の指定（無期限維持）**: `"idle_timeout_sec": 0` を指定すると、全プロトコルで無通信タイムアウトを無効化し、OS の TCP Keep-Alive（30秒間隔）のみで接続を常時維持します。

---

## 5. 🏛️ アーキテクチャと詳細な仕組み（技術解説）

### 5-1. 透過プロキシ ＆ ハイブリッド中継の仕組み

OS のネットワーク層（Windows Filtering Platform）でパケットを直接横取りしてローカルリスナー（`18080`）へ引き込む透過ルートと、WSL からの明示的 CONNECT ルートが同一エンジンで処理されます。

```text
┌────────────────────────────────────────────────────────┐
│ 【Windows ホスト側アプリ】                             │
│   ブラウザ / SSH / RDP / 各種CLI（プロキシ設定なし）    │
└────────────────────────┬───────────────────────────────┘
                         ▼
        [ ① WinDivert（カーネルパケット捕捉）]
                         │
                         ▼
┌────────────────────────────────────────────────────────┐     ┌────────────────────────┐
│ [ ② ローカルプロキシ（[::]:18080 Dual-Stack）]          │ ◄───┤ 【WSL2 / 外部ツール】   │
│   ・透過接続: NATテーブル逆引きで本来の宛先を特定      │     │   export https_proxy   │
│   ・直接接続: HTTP CONNECT / GET を自動パース          │     └────────────────────────┘
└────────────────────────┬───────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────┐
│ [ ③ フィルタエンジン（常時適用）]                      │
│   ├──【不許可】──→ ❌ 通信強制切断 (403 / RST)         │
│   └──【許可】                                          │
└────────────────────────┬───────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────┐
│ [ ④ 動的プロトコルディスパッチャー ]                   │
│   ├──【非Web通信 または 上位プロキシ未設定】           │
│   │     └──→ 本アプリが相手先へ直接接続（DIRECT）       │
│   └──【Web通信 かつ 上位プロキシ設定時】               │
│         └──→ Windows統合認証（SSPI/NTLM）で自動ログイン │
└────────────────────────┬───────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────┐
│ [ ⑤ 上流サーバー / 社内プロキシサーバー ]              │
└────────────────────────────────────────────────────────┘
```

### 5-2. ポート非依存のL7プロトコルシグネチャ自動判別
通信開始時の先頭数バイト（暗号化ペイロードの復号は不要）から、**ポート番号に依存せずプロトコル種別を瞬時に自動判別**します：

| プロトコル | 先頭バイトシグネチャ（RFC/標準仕様） | 抽出情報 / 動作 |
| :--- | :--- | :--- |
| **HTTPS (TLS)** | `0x16 0x03` (TLS ClientHello) | **SNI（サーバー名）** を抽出してポリシー判定・上位プロキシへ中継 |
| **HTTP (平文)** | `GET `, `POST `, `HEAD `, `CONNECT ` 等 | **`Host:` ヘッダー** を抽出してポリシー判定・上位プロキシへ中継 |
| **Microsoft RDP** | `0x03 0x00 ... 0xE0` (TPKT v3 + X.224 CR PDU) | 非Web直接通信（DIRECT）+ **アイドルタイムアウト解除（常時接続）** |
| **SSH** | `"SSH-"` (RFC 4253 バージョン交換バナー) | 非Web直接通信（DIRECT）+ **アイドルタイムアウト解除（常時接続）** |
| **VNC** | `"RFB "` (RFC 6143 バナー) | 非Web直接通信（DIRECT）+ **アイドルタイムアウト解除（常時接続）** |
| **その他 TCP** | 上記以外のバイナリストリーム | 宛先 IP:Port に基づき直接通信（DIRECT） |

---

## 6. 📁 ディレクトリ構成

```text
transport_proxy/
├── cmd/
│   └── tproxy/
│       └── main.go              # エントリポイント、管理者権限チェック、Graceful Shutdown
├── internal/
│   ├── config/                  # 設定読み込み、ホットリロード、WinDivertフィルタ生成
│   ├── dns/                     # DNS-to-DoH自動昇格、RFC 1035/8484パーサー、キャッシュ
│   ├── filter/                  # ホワイトリスト/ブラックリスト/ALL-PASS判定エンジン
│   ├── interceptor/             # WinDivert APIラッパー、ゼロアロケーションNAT、L7シグネチャ解析
│   ├── pac/                     # WinHTTP WPAD/PAC自動解決、キャッシュエンジン
│   ├── proxy/                   # 透過＋明示的ハイブリッドプロキシサーバー、SSPI、双方向パイプ
│   ├── sspi/                    # Windows SSPI (secur32.dll) NTLM/Negotiate 認証
│   └── logger/                  # デバッグ・コンソールロガー
├── tools/
│   └── mock_proxy/              # 検証用モックプロキシ（NTLM/SSO認証、PACサーバー内蔵）
├── WinDivert.dll / .sys         # WinDivert x64 ドライバ・ライブラリ
├── config.json                  # 設定ファイル
└── README.md                    # 本ドキュメント
```

---

## 7. 🛠️ 動作要件・ビルド手順

- **OS**: Windows 10 / 11 / Windows Server 2016 以降 (64-bit)
- **権限**: 管理者権限（WinDivert ドライバロード用）
- **Go 言語**: Go 1.21 以上（CGO 不要、標準コンパイラのみでビルド可能）

```powershell
# リリース用最適化ビルド
go build -v -ldflags="-s -w" -o tproxy.exe ./cmd/tproxy

# 全テストの実行
go test -count=1 ./...
```
