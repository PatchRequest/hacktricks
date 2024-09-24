# macOS Keychain

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Main Keychains

* **ユーザーキーチェーン** (`~/Library/Keychains/login.keychain-db`) は、アプリケーションパスワード、インターネットパスワード、ユーザー生成証明書、ネットワークパスワード、ユーザー生成の公開/秘密鍵などの**ユーザー固有の資格情報**を保存するために使用されます。
* **システムキーチェーン** (`/Library/Keychains/System.keychain`) は、WiFiパスワード、システムルート証明書、システムプライベートキー、システムアプリケーションパスワードなどの**システム全体の資格情報**を保存します。
* `/System/Library/Keychains/*` には、証明書などの他のコンポーネントを見つけることができます。
* **iOS** には、`/private/var/Keychains/` に1つの**キーチェーン**があります。このフォルダーには、`TrustStore`、証明書機関（`caissuercache`）、およびOSCPエントリ（`ocspache`）のデータベースも含まれています。
* アプリは、アプリケーション識別子に基づいて、キーチェーン内のプライベートエリアのみに制限されます。

### Password Keychain Access

これらのファイルは、固有の保護がなく、**ダウンロード**可能ですが、暗号化されており、**復号化するためにユーザーの平文パスワードが必要**です。復号化には、[**Chainbreaker**](https://github.com/n0fate/chainbreaker)のようなツールが使用できます。

## Keychain Entries Protections

### ACLs

キーチェーン内の各エントリは、さまざまなアクションを実行できる人を規定する**アクセス制御リスト（ACL）**によって管理されています。これには以下が含まれます：

* **ACLAuhtorizationExportClear**: 秘密のクリアテキストを取得することを許可します。
* **ACLAuhtorizationExportWrapped**: 別の提供されたパスワードで暗号化されたクリアテキストを取得することを許可します。
* **ACLAuhtorizationAny**: すべてのアクションを実行することを許可します。

ACLは、これらのアクションをプロンプトなしで実行できる**信頼されたアプリケーションのリスト**を伴います。これには以下が含まれます：

* **N`il`**（認証不要、**誰でも信頼される**）
* **空の**リスト（**誰も**信頼されない）
* **特定の**アプリケーションの**リスト**。

また、エントリには**`ACLAuthorizationPartitionID`**というキーが含まれている場合があり、これは**teamid、apple、**および**cdhash**を識別するために使用されます。

* **teamid**が指定されている場合、**プロンプトなしで**エントリの値に**アクセスする**には、使用されるアプリケーションが**同じteamid**を持っている必要があります。
* **apple**が指定されている場合、アプリは**Apple**によって**署名**されている必要があります。
* **cdhash**が指定されている場合、**アプリ**は特定の**cdhash**を持っている必要があります。

### Creating a Keychain Entry

**`Keychain Access.app`**を使用して**新しい**エントリを作成する際には、以下のルールが適用されます：

* すべてのアプリが暗号化できます。
* **アプリは**エクスポート/復号化できません（ユーザーにプロンプトなしで）。
* すべてのアプリが整合性チェックを確認できます。
* アプリはACLを変更できません。
* **partitionID**は**`apple`**に設定されます。

**アプリケーションがキーチェーンにエントリを作成する**場合、ルールは少し異なります：

* すべてのアプリが暗号化できます。
* **作成アプリケーション**（または明示的に追加された他のアプリ）のみがエクスポート/復号化できます（ユーザーにプロンプトなしで）。
* すべてのアプリが整合性チェックを確認できます。
* アプリはACLを変更できません。
* **partitionID**は**`teamid:[teamID here]`**に設定されます。

## Accessing the Keychain

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

{% hint style="success" %}
**キーチェーンの列挙と秘密のダンプ**は、**プロンプトを生成しない**ものについては、ツール[**LockSmith**](https://github.com/its-a-feature/LockSmith)を使用して行うことができます。

他のAPIエンドポイントは、[**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity\_keychain/libsecurity\_keychain-55017/lib/SecKeychain.h.auto.html)のソースコードで見つけることができます。
{% endhint %}

**Security Framework**を使用して各キーチェーンエントリの**情報**をリストおよび取得することができます。また、AppleのオープンソースCLIツール[**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**も確認できます。** 一部のAPIの例：

* API **`SecItemCopyMatching`**は各エントリに関する情報を提供し、使用時に設定できる属性があります：
* **`kSecReturnData`**：真の場合、データの復号を試みます（ポップアップを避けるために偽に設定）
* **`kSecReturnRef`**：キーチェーンアイテムへの参照も取得します（後でポップアップなしで復号できることがわかった場合は真に設定）
* **`kSecReturnAttributes`**：エントリに関するメタデータを取得
* **`kSecMatchLimit`**：返す結果の数
* **`kSecClass`**：キーチェーンエントリの種類

各エントリの**ACL**を取得：

* API **`SecAccessCopyACLList`**を使用すると、**キーチェーンアイテムのACL**を取得でき、各リストには以下が含まれます：
* 説明
* **信頼されたアプリケーションリスト**。これには以下が含まれる可能性があります：
* アプリ：/Applications/Slack.app
* バイナリ：/usr/libexec/airportd
* グループ：group://AirPort

データをエクスポート：

* API **`SecKeychainItemCopyContent`**はプレーンテキストを取得します
* API **`SecItemExport`**はキーと証明書をエクスポートしますが、コンテンツを暗号化してエクスポートするためにパスワードを設定する必要があるかもしれません

そして、**プロンプトなしで秘密をエクスポートするための要件**は以下の通りです：

* **1つ以上の信頼された**アプリがリストされている場合：
* 適切な**認可**が必要です（**`Nil`**、または秘密情報にアクセスするための認可リストに**含まれている**必要があります）
* コード署名が**PartitionID**と一致する必要があります
* コード署名が1つの**信頼されたアプリ**のものと一致する必要があります（または正しいKeychainAccessGroupのメンバーである必要があります）
* **すべてのアプリケーションが信頼されている**場合：
* 適切な**認可**が必要です
* コード署名が**PartitionID**と一致する必要があります
* **PartitionID**がない場合、これは必要ありません

{% hint style="danger" %}
したがって、**1つのアプリケーションがリストされている**場合、そのアプリケーションに**コードを注入する**必要があります。

**apple**が**partitionID**に示されている場合、**`osascript`**を使用してアクセスできるため、partitionIDにappleを含むすべてのアプリケーションを信頼することができます。**`Python`**もこれに使用できます。
{% endhint %}

### 2つの追加属性

* **Invisible**：エントリを**UI**キーチェーンアプリから**隠す**ためのブールフラグです
* **General**：**メタデータ**を保存するためのもので（したがって、暗号化されていません）
* Microsoftは、機密エンドポイントにアクセスするためのすべてのリフレッシュトークンをプレーンテキストで保存していました。

## 参考文献

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{% hint style="success" %}
AWSハッキングを学び、練習する：<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、練習する：<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で**フォロー**してください 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
