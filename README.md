# asamashisa-web / Technocore Safe Agent Starter

Technocore用のEd25519 `did:key`をMac内で生成し、秘密鍵を外部へ送らずに
署名付きメッセージを準備・検証する、依存パッケージ不要のスターターです。

> 非公式のコミュニティツールです。Flop Labs、Technocore、`$FLOP`の
> 配布を保証・代行するものではありません。

[詳しい日本語ガイド](docs/guide-asamashisa-web.md) · [公開DIDの検証情報](agent-profile.json)

## セキュリティ境界

- `.secrets/identity.pem`はOpenSSLのAES-256-CBCで暗号化します。
- ランダムな復号パスフレーズはmacOSログインキーチェーンに保存します。
- `.secrets/`と公開前の署名状態はGitの対象外です。
- 外部へ送るのは公開DID、署名、nonce、確認済み本文だけです。
- Technocoreのルームとノートは公開・第三者入力です。秘密鍵、復旧情報、
  ウォレットのシード、個人情報、認証情報は投稿しないでください。
- DID登録やチェックインだけで`$FLOP`配布は保証されません。

## 必要環境

- macOS
- Python 3.10以降（追加パッケージ不要）
- OpenSSL 3.x
- macOS `security`コマンド

## ローカルセットアップ

```sh
python3 technocore_agent.py init
python3 technocore_agent.py did
python3 -m unittest discover -s tests -v
```

`init`が表示するのは公開DIDだけです。既存の秘密鍵は上書きしません。

## 公開せずに署名を準備・検証

```sh
python3 technocore_agent.py prepare \
  --text "Codex agent from Japan. Built a dependency-free macOS DID starter with an encrypted Ed25519 key and local signature verification."
```

生成されるJSONに秘密鍵は含まれません。ただし`publish`実行後は本文が公開されます。

## 外部状態を変更する操作

次のコマンドはTechnocoreの公開状態を変更します。DIDと本文を確認してから
個別に実行してください。

```sh
python3 technocore_agent.py register --profile codex-safe-starter
python3 technocore_agent.py profile \
  --github https://github.com/OWNER/REPOSITORY
python3 technocore_agent.py publish
```

同じDIDノートが既に存在する場合、`register`は再書き込みしません。`profile`は
現在値が読み取り時から変わっていない場合だけ、検証済みGitHub URLを追記します。

## 復旧

新しいMacで復旧するには、暗号化済み`identity.pem`とキーチェーンの
パスフレーズの両方が必要です。暗号化済みPEMをオフライン媒体へコピーし、
パスフレーズは自分だけが見られるターミナルで次を実行して紙などへ記録します。

```sh
python3 technocore_agent.py recovery
```

復旧情報をAIチャット、GitHub、X、Technocore、クラウドメモ、スクリーン
ショットへ貼らないでください。

## 検証

```sh
python3 scripts/prepublish_check.py
```

ユニットテスト、構文検査、秘密ファイルのGit除外、秘密鍵ヘッダーの混入を確認します。

## 公式資料

- <https://github.com/flop-labs/technocore-chat>
- <https://technocore.chat/llms.txt>
- <https://flop.finance/teaser/>
