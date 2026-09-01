# tproxy — Cross-Platform Transparent Proxy Gateway

> **Windows・Ubuntu (Linux) 両対応。** OS やアプリの設定を一切変えずに、PC 上の全通信をポリシー制御・監査・中継する多機能プロキシゲートウェイ。

---

## 📌 概要

`tproxy` は「**完全透過プロキシ**（Transparent）」と「**明示的フォワードプロキシ**（HTTP CONNECT）」を一つのバイナリで提供します。  
同一の `config.json` で **Windows ホスト・Ubuntu ネイティブホスト・WSL2** の通信を同一ポリシーで制御できます。

| 対象環境 | 制御方式 | アプリ側の設定 | パケット取得方法 |
| :--- | :--- | :---: | :--- |
| **Windows ホスト**（ブラウザ・SSH・RDP・CLI 等） | 完全透過プロキシ | **不要** | WinDivert（WFP カーネル層） |
| **Ubuntu ホスト**（curl・apt・Docker 等） | 完全透過プロキシ | **不要** | `iptables` REDIRECT + `SO_ORIGINAL_DST` |
| **WSL2**（Ubuntu・curl・apt・Docker 等） | 完全透過プロキシ | **不要** | WinDivert（WFP カーネル層。要ミラーモード） |

---

> **⚠️ ビルド済みバイナリ（exe 等）を配布していない理由**
>
> 本ソフトウェアは、OS のネットワーク通信をカーネル層で直接操作するという性質上、利用者に「このソフトに悪意がないこと」を確信したうえで使っていただきたいと考えています。そのため、**ビルド済みの実行ファイル（exe・バイナリ）はあえて配布していません。**
>
> ソースコードをご自身の目で確認し、納得したうえで `go build` でビルドしてください。すべてのコードはこのリポジトリ内で公開されています。

---

## 🚀 クイックスタート

### Windows 版

#### 事前準備: WinDivert の配置（初回のみ）

[WinDivert 公式](https://reqrypt.org/windivert.html) または [GitHub Releases](https://github.com/basil00/Divert/releases) から最新 zip をダウンロードし、`x64\` フォルダ内の以下 2 ファイルを `tproxy.exe` と同じフォルダに置きます：

- `WinDivert.dll`
- `WinDivert64.sys`

#### Step 1: ビルド

```powershell
go build -ldflags="-s -w" -o tproxy.exe ./cmd/tproxy
```

#### Step 2: 管理者権限で起動

**「管理者として実行」した PowerShell** で起動します（WinDivert ドライバのロードに必要）：

```powershell
.\tproxy.exe
```

これだけで、Windows PC 上のすべての通信が設定不要で透過的に制御されます。

#### 停止

`Ctrl + C` を押すと、WinDivert によるパケット横取りが 100% 自動解除され、通常通信に即時復元します。

---

### Ubuntu (Linux) 版

ドライバの追加インストールは不要です。Linux 標準の `iptables` を使用します。

#### Step 1: ビルド

Ubuntu 上でビルドする場合：

```bash
go build -ldflags="-s -w" -o tproxy ./cmd/tproxy
```

Windows からクロスコンパイルする場合：

```powershell
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -ldflags="-s -w" -o tproxy ./cmd/tproxy
```

#### Step 2: sudo で起動

```bash
sudo ./tproxy
```

起動すると、Ubuntu ホスト上の全アプリ（curl・apt・ブラウザ・Docker 等）の通信が自動的に透過制御されます。

#### 停止

`Ctrl + C` を押すと、`iptables` ルールが 100% 自動削除され、通常通信へ即時復元します。

#### systemd による常駐サービス化（推奨）

付属スクリプトを実行するだけで自動起動サービスとして登録できます：

```bash
sudo ./scripts/install-ubuntu.sh
```

| コマンド | 説明 |
| :--- | :--- |
| `sudo systemctl status tproxy` | サービス状態確認 |
| `sudo journalctl -u tproxy -f` | リアルタイムログ |
| `sudo tproxy -cleanup` | 万一のルール手動削除 |

---

### WSL2 での使い方

WSL2 上で Linux 版 `tproxy` を実行する場合、または Windows ホスト側の `tproxy` と連携する場合、WSL2 の DNS 設定（`dnsTunneling`）とネットワークモードを設定します。

#### ① `.wslconfig` でミラーモードと DNS トンネリング無効化を設定

`%UserProfile%\.wslconfig` に以下を設定します：

```ini
[wsl2]
networkingMode=mirrored
dnsTunneling=false
firewall=true
```

> **💡 なぜ `dnsTunneling=false` が必要なのか？**:
> `dnsTunneling=true`（WSL2 のデフォルト）の場合、DNS 問い合わせが Windows 側の内部プロキシ（`127.0.0.42`）へ直接渡されるため、`iptables` のローカル通信除外ルール（`127.0.0.0/8`）によって DoH 昇格をバイパスしてしまいます。
> **`dnsTunneling=false`** に設定することで、WSL2 内の DNS クエリが外部宛て UDP 53 パケットとして送信され、`tproxy` の DoH 変換エンジン（ポート `:18180`）で確実にキャプチャ・DoH 昇格（Cloudflare Security 等）・インメモリキャッシュされるようになります。

設定後、PowerShell で `wsl --shutdown` を実行して WSL を再起動します。これだけで WSL2 上の curl・apt・Docker 等の通信が設定不要で tproxy に制御されます。

#### ② プロキシ環境変数（おまけ）

一部の特殊なツールでシステム設定が効かないケースなどに備え、明示的なプロキシ接続も引き続きサポートされています：

```bash
export http_proxy=http://127.0.0.1:18080
export https_proxy=http://127.0.0.1:18080
export all_proxy=http://127.0.0.1:18080
```

> **🔒 セキュリティ**: 明示的プロキシ（ポート `18080`）への接続元が `127.0.0.1` / `::1` または WSL 仮想サブネット以外の場合、即座に `403 Forbidden` で遮断されます（オープンプロキシ化防止）。

---

## ⚙️ 起動オプション

| オプション | 説明 |
| :--- | :--- |
| *(なし)* | 通常起動。主要アクセスログをコンソール表示 |
| `-v` / `-verbose` | 詳細ログ表示（パケット詳細・NAT 書き換え等） |
| `-d` / `-dry-run` | ドライラン（遮断せず監査ログ出力のみ） |
| `-log <file>` / `-l <file>` | コンソールと同時にファイルへログ保存 |
| `-c <file>` | 設定ファイルのパスを指定 |
| `-V` / `-version` | バージョン情報を表示して終了 |
| `-cleanup` | 異常終了時に残った OS レベルの転送ルール（iptables 等）を削除して終了 |

```powershell
# 例: 詳細ログ + ファイル保存
.\tproxy.exe -v -log tproxy.log
```

**ログ出力例:**

```text
[ALLOW] DNS-DoH          | Client: 192.168.1.10:54320 | Target: 1.1.1.2:53           | github.com (A) -> DoH (15ms)
[ALLOW] HTTPS            | Client: 192.168.1.10:54321 | Target: github.com:443        -> DIRECT
[ALLOW] HTTPS (EXPLICIT) | Client: 127.0.0.1:45530    | Target: api.example.com:443   -> DIRECT
[BLOCK] HTTPS (EXPLICIT) | Client: 127.0.0.1:45532    | Target: blocked-site.com:443  -> Blocked by policy
[CLOSE] Client: 127.0.0.1:45530 | Target: api.example.com:443 | Sent: 1.7 KB | Recv: 91.6 KB | Duration: 451ms
```

---

## 📋 config.json 設定リファレンス

設定ファイルは**ホットリロード対応**です。アプリ稼働中に編集・保存するだけで、再起動なしに即座に反映されます（デフォルト: 5 秒周期で変更検知）。

### 全パラメータ一覧

| キー | 型 | デフォルト | 説明 |
| :--- | :---: | :---: | :--- |
| `filter_mode` | `string` | `"whitelist"` | フィルタリングモード。`"whitelist"` / `"blacklist"` / `"all"`（全通し）。`"none"` / `"off"` / `"disabled"` / `"passthrough"` も全通しのエイリアスとして使用可 |
| `allowed_domains` | `[]string` | `[]` | **ホワイトリスト**で許可するドメイン・ワイルドカード（例: `"*.github.com"`） |
| `allowed_ips` | `[]string` | `[]` | **ホワイトリスト**で許可する IP / CIDR（例: `"10.0.0.0/8"`） |
| `blocked_domains` | `[]string` | `[]` | **ブラックリスト**で遮断するドメイン・ワイルドカード |
| `blocked_ips` | `[]string` | `[]` | **ブラックリスト**で遮断する IP / CIDR |
| `listen_addr` | `string` | `"0.0.0.0:18080"` | ローカルプロキシの待受けアドレス（ポート衝突時は自動で別ポートへ退避） |
| `pac_url` | `string` | `""` | 上位プロキシの PAC/WPAD URL（例: `"http://wpad.corp.local/wpad.dat"`）。**※Windows版のみ対応（Ubuntu版では無視されます）** |
| `upstream_proxy` | `string` | `""` | 固定上位 HTTP プロキシ URL（例: `"http://proxy.corp.local:8080"`） |
| `bypass_sspi` | `bool` | `false` | `true` で上位プロキシへの Windows 統合認証（SSPI/NTLM）を無効化 |
| `dns_servers` | `[]string` | `[]` | 上位 DNS サーバーの IP 一覧（IPv4: `"192.168.1.1"`, `"169.254.169.254"`, IPv6: `"2001:db8::1"` 等）。指定時は平文 UDP 53 直通バイパス。<br>**未指定（`[]`）時は自動で Cloudflare Security DoH（IPv4: `1.1.1.2`, `1.0.0.2` / IPv6: `2606:4700:4700::1112`, `2606:4700:4700::1002`）で暗号化解決** |
| `doh_enabled` | `bool` | `true` | DNS クエリを自動的に DoH（DNS over HTTPS）に昇格するかどうか。`false` にすると DoH 変換を無効化し、平文 UDP 53 のみで名前解決 |
| `doh_timeout_sec` | `int` | `3` | DoH クエリのタイムアウト秒数 |
| `fallback_to_udp` | `bool` | `true` | DoH 失敗時に平文 UDP 53 へフォールバックするかどうか |
| `dns_cache_enabled` | `bool` | `true` | インメモリ DNS キャッシュ（2 回目以降 0 ms 応答）の有効/無効 |
| `dns_cache_ttl_sec` | `int` | `300` | DNS キャッシュの最大保持秒数（TTL） |
| `connect_timeout_sec` | `int` | `10` | 上流サーバー / 上位プロキシへの TCP 接続タイムアウト秒数 |
| `idle_timeout_sec` | `int` | `60` | 無通信接続の切断秒数。`0` で無期限維持（RDP・SSH に推奨） |
| `reload_interval_sec` | `int` | `5` | 設定ファイルの変更検知周期（秒） |
| `log_file` | `string` | `""` | ログ出力先ファイルパス。空文字はコンソールのみ |
| `dry_run` | `bool` | `false` | `true` で通信を変更せず監査ログ出力のみのドライランモード |
| `divert_filter` | `string` | `""` (自動生成) | WinDivert のカスタムキャプチャ条件（通常は空推奨） |

### 設定例

#### パターン 1: ホワイトリスト（推奨・セキュア運用）

指定したドメイン・IP 宛てのみを許可し、未知のサイトをすべて遮断します：

```json
{
  "filter_mode": "whitelist",
  "allowed_domains": [
    "github.com", "*.github.com", "*.githubusercontent.com",
    "google.com", "*.google.com",
    "*.microsoft.com", "*.windowsupdate.com"
  ],
  "allowed_ips": [
    "127.0.0.1", "::1",
    "192.168.0.0/16", "10.0.0.0/8"
  ]
}
```

#### パターン 2: ブラックリスト

特定のサイト・IP のみ遮断し、それ以外をすべて許可します：

```json
{
  "filter_mode": "blacklist",
  "blocked_domains": ["*.example-blocked.com", "badsite.example.org"],
  "blocked_ips": ["198.51.100.25", "203.0.113.0/24"]
}
```

#### パターン 3: 全通し（フィルタ無効）

通信を一切遮断せず全通しで使う場合（動作確認・テスト用）：

```json
{
  "filter_mode": "all"
}
```

#### パターン 4: 社内プロキシ・PAC 連携

```json
{
  "filter_mode": "all",
  "pac_url": "http://wpad.corp.local/wpad.dat",
  "upstream_proxy": "http://proxy.corp.local:8080"
}
```

> **注意 (Ubuntu版について)**: `pac_url` による PAC 解析は Windows 版の独自機能（WinHTTP API 利用）のため、**Ubuntu (Linux) 版では機能しません（指定しても無視され直接接続になります）**。Ubuntu で上位プロキシを利用する場合は、PAC は使わずに `"upstream_proxy"` で直接指定するか、OS の環境変数（`http_proxy` / `https_proxy`）を設定してください。
>
#### パターン 5: DNS 設定（社内/クラウド DNS 直通 vs デフォルト DoH）

**A. 社内 DNS やクラウド仮想マシン（GCP / AWS 等）の場合（直通バイパス）**:
IPv4 アドレス（`"169.254.169.254"`, `"10.0.0.2"`）、IPv6 アドレス（`"2001:db8::53"`）を直接指定します：
```json
{
  "dns_servers": [
    "169.254.169.254",
    "10.0.0.2",
    "2001:db8::53"
  ]
}
```
> 社内 DNS（`10.x.x.x`）や GCP メタデータ DNS（`169.254.169.254`）、AWS VPC DNS（`10.0.0.2`）を指定すると、そのサーバー宛ての平文 UDP 53 通信が直接バイパスされ、社内ドメイン（`*.corp`）やクラウド内部ドメイン（`*.internal`）が 100% 安定して解決されます。

**B. 一般インターネット環境の場合（自動 DoH 暗号化）**:
```json
{
  "dns_servers": []
}
```
> `dns_servers` を空配列 `[]` または未指定にすると、**Cloudflare Security DNS (`1.1.1.2`, `1.0.0.2`, `2606:4700:4700::1112`, `2606:4700:4700::1002`)** を使用し、自動的に **DoH（HTTPS 暗号化）** に変換して送信されます（マルウェア・フィッシング自動遮断）。

#### パターン 6: 常時接続維持（RDP・SSH 用）

```json
{
  "idle_timeout_sec": 0
}
```

`"idle_timeout_sec": 0` で全プロトコルの無通信タイムアウトを無効化し、OS の TCP Keep-Alive（30 秒間隔）のみで常時維持します。  
大容量ダウンロード中は「データが流れている限りタイムアウトが自動延長」されるため、数十 GB のファイル転送も途中切断しません。

---

## 🏛️ アーキテクチャ解説

### Windows 版の仕組み

Windows 版は **WinDivert**（Windows Filtering Platform ベースのカーネルドライバ）を使い、OS ネットワーク層でアウトバウンドパケットを直接キャプチャします。アプリ側にプロキシ設定は一切不要です。

```text
【Windows ホスト上のアプリ】
  ブラウザ / SSH / RDP / curl など（プロキシ設定なし）
         |
         v  カーネル層でキャプチャ（WFP）
  [1] WinDivert
         |
         +-- UDP 53 (DNS) --> DNS ワーカープール（16並列）
         |                      |  DoH へ昇格 + インメモリキャッシュ
         |                      v
         |                    WinDivert で偽造応答を直接インジェクト
         |
         +-- TCP (その他)  --> パケットをループバックへリダイレクト
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
       |  上位プロキシ設定時 --> SSPI/NTLM 自動認証 --> プロキシ経由
       v
  [5] 上流サーバー / 社内プロキシ
```

> DNS パケットはカーネル層で捕捉・応答まで完結するため、DoH 昇格後の応答パケットも WinDivert 経由で直接クライアントへ書き戻されます。

**終了時の安全性**: `Ctrl + C` で WinDivert ドライバが即時アンロードされ、パケット横取りが完全解除されます。OS の通常通信へ瞬時に復元します。

---

### Ubuntu (Linux) 版の仕組み

Ubuntu 版は Linux 標準の **Netfilter** (`iptables`) を使い、ローカル発の TCP/UDP パケットをローカルプロキシへリダイレクトします。カーネル外部ドライバの追加インストールは不要です。

```text
【Ubuntu ホスト上のアプリ】
  curl / apt / ブラウザ / Docker など（プロキシ設定なし）
         |
         v  iptables OUTPUT チェイン（TPROXY_RULES カスタムチェイン）
  [1] Netfilter REDIRECT ルール
         |
         +-- UDP 53 (DNS) --> ローカル UDP リスナー :18180（プロキシポート + 100）
         |                      |  SO_MARK=0xff でループ防止
         |                      |  DoH へ昇格 + インメモリキャッシュ
         |                      |  passthrough 時は SO_MARK 付きで平文 UDP 転送
         |                      v
         |                    UDP 応答をクライアントへ直接返送
         |
         +-- TCP (その他)  --> ローカルプロキシ :18080
                                |
                                v
  [2] ローカルプロキシ 0.0.0.0:18080
       |  SO_ORIGINAL_DST で本来の宛先 IP:Port を取得
       v
  [3] フィルタエンジン（ホワイト/ブラックリスト）
       |  不許可 --> 強制切断
       |  許可
       v
  [4] L7 プロトコルディスパッチャー
       |  上位プロキシ未設定 --> DIRECT 接続
       |  上位プロキシ設定時 --> プロキシ経由
       v
  [5] 上流サーバー / 社内プロキシ
```

> DNS は TCP プロキシとは独立した UDP リスナー（プロキシポート + 100、デフォルト `:18180`）で処理されます。プロキシ自身が発する DoH 通信および TCP アウトバウンド接続には `SO_MARK=0xff` を付与して iptables ルールをバイパスし、自己ループを防止しています。

**終了時の安全性**: `Ctrl + C` で `iptables` / `ip6tables` のルールが全自動削除されます。`systemd` 経由の停止でも同様に自動クリーンアップされます。

---

### Windows 版と Ubuntu 版の違い

| 比較項目 | Windows 版 | Ubuntu 版 |
| :--- | :--- | :--- |
| **パケット取得レイヤー** | WFP（Windows Filtering Platform）カーネル層 | Netfilter / iptables（Linux カーネル） |
| **使用コンポーネント** | WinDivert.dll + WinDivert64.sys（外部ドライバ） | iptables / ip6tables（OS 標準） |
| **宛先 IP の復元方法** | WinDivert NAT テーブル逆引き | `SO_ORIGINAL_DST` ソケットオプション |
| **DNS パケットの取得方法** | WinDivert が UDP 53 をカーネル層で直接キャプチャ | iptables REDIRECT で別ポート（プロキシポート + 100）の UDP リスナーへ転送 |
| **DNS 応答の返送方法** | WinDivert で偽造パケットを直接インジェクト | UDP ソケットでクライアントへ直接 `WriteTo` |  
| **DoH ループ防止** | WinDivert フィルタのポート範囲で自動除外 | プロキシ発パケットに `SO_MARK=0xff` を付与して iptables をバイパス |
| **起動権限** | 管理者（Administrator）必須 | sudo 必須 |
| **終了時のクリーンアップ** | WinDivert ドライバ自動アンロード | iptables / ip6tables ルール自動削除 |
| **上位プロキシ認証** | SSPI / NTLM / Kerberos（Windows SSO）対応 | 基本認証のみ（SSPI 非対応） |
| **常駐サービス化** | 非対応（手動起動） | `systemd` スクリプト付属 |
| **WSL2 との関係** | WSL2 の通信源として機能 | WSL2 自体が Ubuntu 版相当 |

---

### WSL2 のキャプチャ方式（NAT モード vs ミラーモード）

- **NAT モード（旧仕様・デフォルト）**: WSL2 は独立した仮想 NIC を持ち、Hyper-V vSwitch（Layer 2）を通じて物理アダプタへ直接送出されるため、Windows 側の WFP（WinDivert）ではキャプチャできません。
- **ミラーモード（Windows 11 22H2 以降）**: WSL2 が Windows ホストと IP ネットワークスタックを共有するため、WSL2 内部から発するパケットも Windows ホスト上のアプリと全く同様に **WinDivert で完全に透過キャプチャ可能** です。

そのため、tproxy を WSL2 で透過的に利用する場合は、`networkingMode=mirrored` の設定を強く推奨します。

---

### L7 プロトコル自動判別

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
│   └── main.go              # エントリポイント・権限チェック・Graceful Shutdown
├── internal/
│   ├── config/              # 設定読み込み・ホットリロード・WinDivert フィルタ生成
│   ├── dns/                 # DNS-to-DoH 昇格・RFC 1035/8484 パーサー・キャッシュ
│   ├── filter/              # ホワイトリスト/ブラックリスト判定エンジン
│   ├── interceptor/         # WinDivert ラッパー・NAT・L7 シグネチャ解析
│   ├── pac/                 # WinHTTP WPAD/PAC 自動解決・キャッシュ
│   ├── proxy/               # 透過 + 明示的ハイブリッドプロキシ・SSPI・双方向パイプ
│   ├── sspi/                # Windows SSPI (secur32.dll) NTLM/Negotiate 認証
│   └── logger/              # デバッグ・コンソールロガー
├── tools/mock_proxy/        # 検証用モックプロキシ（NTLM/SSO 認証・PAC サーバー内蔵）
├── scripts/
│   ├── install-ubuntu.sh    # Ubuntu systemd サービス登録スクリプト
│   └── tproxy.service       # systemd ユニットファイル
├── WinDivert.dll            # WinDivert x64 ライブラリ
├── WinDivert64.sys          # WinDivert x64 カーネルドライバ
├── config.json              # 設定ファイル
└── config.json.sample       # 設定ファイルのサンプル（全パラメータ記載）
```

---

## 🛠️ 動作要件

| 項目 | Windows 版 | Ubuntu 版 |
| :--- | :--- | :--- |
| **OS** | Windows 10 / 11 / Server 2016 以降（64-bit） | Ubuntu 20.04 以降 / 任意の Linux |
| **権限** | 管理者（Administrator） | sudo |
| **追加ドライバ** | WinDivert.dll + WinDivert64.sys | 不要（iptables 使用） |
| **Go バージョン** | Go 1.21 以上（CGO 不要） | Go 1.21 以上（CGO 不要） |

```powershell
# Windows: リリースビルド
go build -ldflags="-s -w" -o tproxy.exe ./cmd/tproxy

# Ubuntu: リリースビルド
go build -ldflags="-s -w" -o tproxy ./cmd/tproxy

# テスト実行（共通）
go test -count=1 ./...
```
