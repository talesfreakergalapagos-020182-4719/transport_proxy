# Windows Transparent Proxy & Filter (tproxy)

> ### 🚫 OS のプロキシ設定も、アプリごとの設定も、一切不要。
> **ブラウザ・SSH・RDP・CLI ツール・WSL——すべてが、触らずに透過的に制御・中継される。**

これが `tproxy` の最大の強みです。

一般的なプロキシツールは、ブラウザの設定画面を開き、`HTTP_PROXY` 環境変数を設定し、アプリごとに個別対応が必要です。  
`tproxy` は違います。**Windows のネットワーク層に直接介入し、OS・アプリの設定を一切変えることなく**、PC 上のすべての TCP/UDP 通信を透過的に制御します。

> 💡 **WSL（Windows Subsystem for Linux）も対象です。** WSL2 の通信はホスト Windows のネットワークスタックを経由するため、Linux 側のアプリが発する通信も `tproxy` の制御・フィルタリング対象になります。WSL 内で個別にプロキシ設定する必要はありません。

---

それを実現する **4 つの核心技術**：

| | 強み | 何が嬉しいか |
|:---:|:---|:---|
| ① | 🌐 **OS・アプリ設定ゼロの透過制御** | プロキシ設定なしで全アプリの通信を自動的に透過制御・中継。導入コストほぼゼロ |
| ② | 🚦 **接続先のホスト・IP フィルタリング** | ドメイン・IP アドレスを許可リスト（ホワイトリスト）または禁止リスト（ブラックリスト）で指定。ワイルドカード（`*.example.com`）や CIDR（`10.0.0.0/8`）にも対応 |
| ③ | 🧠 **L7 プロトコル自動判別** | ポート番号が変わっても TLS / HTTP / SSH / RDP / VNC をシグネチャで確実に識別、迂回不可能 |
| ④ | 🛡️ **DNS-over-HTTPS 自動昇格** | 平文 DNS（UDP 53）を暗号化 DoH へ透過変換。DNS 盗聴・改ざんをゼロ設定で遮断 |
| ⑤ | 🏢 **Windows SSO 統合認証** | 社内 NTLM プロキシへ Windows サインイン資格情報で自動ログイン。パスワード不要 |
| ⑥ | 🔒 **完全ローカル処理・外部送信なし** | すべての制御・フィルタリングは PC 上でのみ完結。通信データが悪意ある外部サーバへ送信される心配はありません |

---

## 1. 🚀 クイックスタート（3ステップで今すぐ使う）

理屈抜きで、今すぐ手元で動かす手順です。

### 📦 事前準備: WinDivert の入手（初回のみ）
本アプリはパケット制御に **WinDivert** を使用します。`WinDivert.dll` と `WinDivert64.sys` を `tproxy.exe` と同じフォルダに配置してください：

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

これだけで、PC上のすべての通信が透過的に保護・制御されます（ブラウザやアプリの設定変更は一切不要です）。

### 🛑 停止方法
コンソールで **`Ctrl + C`** を押すと、直ちにパケットの横取りが 100% 自動解除され、OS 標準の通常通信へ瞬時に復元して安全に終了します。

---

## 2. 📖 基本的な使い方・コマンド集

### ① 通常起動（推奨）
主要なアクセスログのみをシンプルに出力します：
```powershell
.\tproxy.exe
```
**ログ出力例:**
```text
[ALLOW] DNS-DoH | Client: 192.168.1.50:54320 | Target: 1.1.1.2:53                    | Query: github.com                (A) -> DoH (15ms)
[ALLOW] HTTPS   | Client: 192.168.1.50:54321 | Target: github.com:443                -> DIRECT
[ALLOW] HTTPS   | Client: 192.168.1.50:54322 | Target: google.com:443                -> PROXY (http://proxy.corp.local:8080)
[BLOCK] DNS     | Client: 192.168.1.50:54323 | Target: 1.1.1.2:53                    | Query: dangerous-site.com        (A) -> Blocked by policy
[BLOCK] HTTPS   | Client: 192.168.1.50:54324 | Target: dangerous-site.com:443        -> Blocked by policy
[CLOSE] Client: 192.168.1.50:54321 | Target: github.com:443 | Sent: 4.2 KB | Recv: 28.5 KB | Duration: 350ms
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
**ドライランログ出力例:**
```text
[DRY-RUN] HTTPS   | WOULD ALLOW | Client: 192.168.1.50:54321 | Target: github.com:443 -> Upstream: DIRECT
[DRY-RUN] HTTPS   | WOULD BLOCK | Client: 192.168.1.50:54323 | Target: dangerous-site.com:443 -> Blocked by policy
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

### ⑥ 動作確認方法
アプリを起動した状態で、別ウィンドウから自由に通信してみてください（プロキシ設定は不要です）：
```powershell
# Webアクセス（HTTPS）のテスト
curl.exe https://github.com

# SSH等の非Webアクセスのテスト
ssh git@github.com
```

---

## 3. ⚙️ 設定ファイル（`config.json`）の書き方

設定ファイルは **アプリ稼働中に編集・保存しても、再起動不要で即座に自動反映（ホットリロード）** されます。

### パターン 1: ホワイトリスト形式（おすすめ・セキュア運用）
指定したドメイン・IP 宛てのみを許可し、未知のサイトをすべて自動遮断します：
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
    "*.badsite.com",
    "*.tiktok.com",
    "twitter.com",
    "x.com"
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

## 4. 🧪 動作確認用モックプロキシツール (`tools/mock_proxy/`)

手元に社内プロキシや PAC サーバーがない環境でも、ローカルだけで上位プロキシ中継や NTLM / SSO 認証の動作テストができるツールを同梱しています。

### 使い方（PowerShell を 2 つ開いてテスト）

1. **【ターミナル 1】モックプロキシを起動（一般ユーザー権限でOK）**
   ```powershell
   # NTLM / 統合Windows認証 (SSO) テストモードで起動
   go run ./tools/mock_proxy -auth ntlm
   ```

2. **【ターミナル 2】`config.json` を設定して `tproxy` を起動（※管理者権限）**
   `config.json` に `"upstream_proxy": "http://127.0.0.1:8080"` を設定して起動：
   ```powershell
   .\tproxy.exe
   ```

3. **【ブラウザ等】Webサイトにアクセス**
   ブラウザから `https://github.com` 等にアクセスすると、自動的に SSPI 認証ハンドシェイクが行われてプロキシ経由で通信が成功します。

---

## 5. 🏛️ アーキテクチャと詳細な仕組み（技術解説）

### 5-1. 透過プロキシの仕組み（なぜ設定不要なのか？）

一般的なプロキシと異なり、OS のネットワーク層（Windows Filtering Platform）でパケットを直接横取りしてローカルリスナー（`18080`）へ引き込みます。

```text
【あなたのPC / アプリケーション】
  ブラウザ / SSH / RDP / 各種CLI（全ポート・プロキシ設定なし）
        │  ▲
        │  │ （行きと帰りのTCPパケット）
        ▼  │
  [ ① WinDivert（インターセプター）]
        │  ▲  宛先を「ローカルプロキシ」へ書き換え（Forward NAT）
        ▼  │  戻りパケットの送信元を本来の宛先IPに復元（Reverse NAT）
  [ ② ローカルプロキシ（[::]:18080 Dual-Stack）]
        │
        │ (1) 接続を受け付け、全通信に対してホワイトリスト/ブラックリスト判定
        ▼
  [ ③ フィルタエンジン（常時適用）]
        │
        ├──【許可リストに無い場合】──────→ ❌ その場で通信強制切断（ブロック）
        │
        └──【許可リストに有る場合（許可）】
              │
              │ (2) 先頭シグネチャを検査してプロトコル種別を動的に判別
              ▼
  [ ④ 動的プロトコルディスパッチャー ]
        │
        ├──【非Web通信（SSH, RDP, VNC, DB等）または 上位プロキシ未設定時】
        │     │
        │     └──→ 本アプリが相手サーバーへ直接接続（DIRECT中継）
        │
        └──【Web通信（HTTP / HTTPS）かつ 上位プロキシ設定時】
              │
              │ (3) Windows統合認証（SSPI）で自動ログイン
              ▼
  [ ⑤ フォワーダー & SSPIネゴシエーター ] ───→ 上位プロキシサーバー (CONNECT)
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

> **💡 非標準ポートへの対応**: ポートフォワーディングや開発環境でポート番号が変更されている場合（例: `2222` の SSH、`3390` の RDP）であっても、シグネチャによって 100% 確実に自動識別されます。

### 5-3. リモートデスクトップ・SSH・常時接続の安定維持機能
リモートデスクトップ（RDP）、SSH ターミナル、データベース接続、クラウド VDI（Azure Virtual Desktop / Chrome Remote Desktop 等）のように、**「ユーザーが無操作で画面を放置する時間が長い通信」** に対する専用の切断防止機構を備えています：

1. **自動アイドルタイムアウト解除**:
   - `RDP`, `SSH`, `VNC` シグネチャが検出された通信、および代表的な管理ポート（`22`, `23`, `3389`, `5900`, `1433`, `1521`, `3306`, `5432`, `6379`, `27017` 等）、VDI サービス宛ては、**無通信タイムアウトを自動的に無効化（`idleTimeout = 0`）** します。
2. **OS TCP Keep-Alive による回線維持**:
   - クライアント側・サーバー側の双方のソケットに対して **30秒間隔の OS TCP Keep-Alive**（`SO_KEEPALIVE`）を有効化し、無操作時でも NAT ルーターやファイアウォールのセッションを維持します。
3. **WinDivert NAT セッションの24時間保持**:
   - WinDivert の NAT マッピング TTL を **24 時間** に設定しており、数時間の離席や無操作の後に操作を再開しても接続が途切れません。

### 5-4. WinDivert による安全な自動復元（クラッシュセーフ）
- 仮想 NIC（TUN/TAP）の作成や、OS ルーティングテーブルの変更を一切行いません。
- アプリ終了時（`Ctrl + C`、タスクキル、万が一のクラッシュ含む）は、WinDivert ハンドルが閉じた瞬間に **Windows カーネルによってパケット横取りが 100% 自動解除** され、OS 標準の通信経路へ安全に復帰します。

### 5-5. 高速化＆高スループット設計
- **WinDivert マルチワーカー (Parallel Workers)**:
  全 CPU コアに分散した独立ワーカーが、専用 OS スレッド（`runtime.LockOSThread()`）で並列にパケット処理を実行。
- **128KB バッファプール ＆ 動的 TCP ウィンドウ**:
  大容量ストリーミング用に 128KB のメモリプールを採用し、Windows TCP 受信ウィンドウの自動チューニング（Dynamic Auto-Tuning）と協調することで、**ギガビット級の高速回線でもスループット低下のない転送** を実現。
- **IPv4 / IPv6 デュアルスタック完全対応**:
  IPv4（`192.168.x.x`）および IPv6（`240d:...`, `fe80::...`）の双方でハードウェアチェックサムオフロードを自動補正し、パケットロス・再送ゼロの通信を提供。

### 5-6. 予約ポートのOS排他保護（PortGuard）
- 自己ループ防止用の予約ポート範囲（`40000-48999`）を、起動時に `netsh excludedportrange (store=active)` で OS カーネルに排他登録。
- 15秒間隔で Windows TCP テーブルを監視し、不審プロセスによる悪用・すり抜けを検知して警告を出力。

### 5-7. DNS問い合わせ（ポート53）の動的DoH自動昇格（DNS-over-HTTPS）

端末やOSのDNS設定、各種CLIツール（`nslookup`等）が送信する平文DNS問い合わせ（UDP 53）を捕捉し、安全な暗号化DoH（RFC 8484）へ自動昇格します。

```text
【アプリ / CLI (nslookup等)】── UDP 53 平文DNSクエリ ──┐
                                                      ▼
                                       [ WinDivert パケット捕捉 ]
                                                      │
                       ┌──────────────────────────────┴──────────────────────────────┐
                       ▼ (IP証明書あり)                                              ▼ (IP証明書なし / 社内DNS)
        [ ① DoH自動昇格 (HTTPS POST) ]                                 [ ② 平文通常パススルー (UDP 53) ]
                       │                                                             │
  ┌────────────────────┴────────────────────┐                                        │
  ▼                                         ▼                                        │
[ インメモリキャッシュ (0ms) ]      [ DoH サーバー (443) ]                           ▼
  │ (TTL期限切れで自動再取得)               │ (Cloudflare / Google等)              [ 家庭内ルーター / 社内DNS ]
  └────────────────────┬────────────────────┘                                        │
                       ▼                                                             ▼
            [ クライアントへDNS応答 ] ◄──────────────────────────────────────────────┘
```

1. **完全メンテナンスフリーな動的DoH自動昇格**:
   - 宛先DNSサーバーのIP自身が正規のSSL/TLS証明書（IP SAN）を持っている場合（例: `1.1.1.2`, `1.1.1.1`, `8.8.8.8`, `9.9.9.9` 等）、手動マッピング表なしで自動的に `https://<IP>/dns-query` （RFC 8484）へ暗号化昇格して問い合わせを実行します。
2. **社内LAN・家庭内ルーターの自動保護（平文パススルー）**:
   - 家庭内ルーター（`192.168.x.x`）や社内Active Directory DNS（`10.x.x.x`）などIP証明書を持たないサーバー宛ては、自動的に通常の平文UDP 53としてパススルーするため、社内ネットワークや家庭環境でも設定変更不要で安全に動作します。
3. **インメモリDNSキャッシュ ＆ 定期自動更新（TTL連携）**:
   - 解決済みレコードをメモリ内にキャッシュし、2回目以降の同一クエリは **0msで即座に応答** します。
   - レコードごとにDNSサーバーが指定する **TTL（有効秒数）** を自動抽出し、有効期限が切れると次回アクセス時に自動で最新のDoH問い合わせを行ってキャッシュを定期的に上書き更新します。
   - `dns_cache_ttl_sec`（デフォルト: 300秒 = 5分）により、最長保持期間の上限を設定可能です。
4. **社内プロキシ（NTLM/SSO）経由でのDoH名前解決**:
   - 上位プロキシが設定されているエンタープライズ環境でも、DoHリクエストをHTTPS CONNECT経由でトンネリング可能なため、ポート53（UDP）が外に出られない環境でも安全に名前解決を行えます。
5. **ポリシー連動（DNSブロッキング）**:
   - ホワイトリスト/ブラックリスト設定でブロック対象のドメインは、DNS段階で即座に `NXDOMAIN` を返して遮断します。

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
│   ├── proxy/                   # 透過TCPプロキシサーバー、非同期先行接続、双方向パイプ転送
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

---

## 8. 🧪 結合テスト (Integration Tests)

本システムは、IPv4/IPv6のそれぞれに対して、ホワイトリスト/ブラックリストのフィルタリングおよび上流プロキシ経由/直接通信が正しく行われるかを検証するための**網羅的な結合テスト (Comprehensive Integration Test)** を実装しています。

以下のコマンドでテストを実行できます：

```powershell
# フィルタリングとプロキシの包括テストを並列実行
go test -v -run TestIntegration_ComprehensiveFilterAndProxy ./internal/proxy
```

このテストでは以下の計16パターンの組み合わせすべてを検証し、許可/拒否の制御が要件通りに動作することを自動で確認します。
* **ネットワーク**: IPv4 / IPv6
* **フィルタモード**: Whitelist (許可リスト) / Blacklist (拒否リスト)
* **プロキシ**: PACファイルによる上流プロキシ利用 (Proxy) / ダイレクト接続 (Direct)
* **通信結果**: 許可 (接続成功) / 拒否 (接続ブロック)

