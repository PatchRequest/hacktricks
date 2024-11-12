# macOS Authorizations DB & Authd



{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## **Athorizarions DB**

`/var/db/auth.db`にあるデータベースは、機密操作を実行するための権限を保存するために使用されるデータベースです。これらの操作は完全に**ユーザースペース**で実行され、通常は**XPCサービス**によって使用され、特定のアクションを実行するために**呼び出し元クライアントが認可されているかどうか**をこのデータベースをチェックして確認します。

最初にこのデータベースは`/System/Library/Security/authorization.plist`の内容から作成されます。その後、一部のサービスがこのデータベースに他の権限を追加または変更することがあります。

ルールはデータベース内の`rules`テーブルに保存され、以下の列を含みます：

* **id**: 各ルールの一意の識別子で、自動的にインクリメントされ、主キーとして機能します。
* **name**: 認可システム内でルールを識別し参照するために使用される一意の名前。
* **type**: ルールのタイプを指定し、認可ロジックを定義するために1または2の値に制限されます。
* **class**: ルールを特定のクラスに分類し、正の整数であることを保証します。
* "allow"は許可、"deny"は拒否、"user"はグループプロパティがアクセスを許可するメンバーシップを示す場合、"rule"は満たすべきルールを配列で示し、"evaluate-mechanisms"は`mechanisms`配列に続き、組み込みまたは`/System/Library/CoreServices/SecurityAgentPlugins/`または/Library/Security//SecurityAgentPlugins内のバンドルの名前です。
* **group**: グループベースの認可のためにルールに関連付けられたユーザーグループを示します。
* **kofn**: "k-of-n"パラメータを表し、満たすべきサブルールの数を決定します。
* **timeout**: ルールによって付与された認可が期限切れになるまでの秒数を定義します。
* **flags**: ルールの動作と特性を変更するさまざまなフラグを含みます。
* **tries**: セキュリティを強化するために許可される認可試行の回数を制限します。
* **version**: バージョン管理と更新のためにルールのバージョンを追跡します。
* **created**: 監査目的のためにルールが作成されたタイムスタンプを記録します。
* **modified**: ルールに対する最後の変更のタイムスタンプを保存します。
* **hash**: ルールの整合性を確保し、改ざんを検出するためのハッシュ値を保持します。
* **identifier**: ルールへの外部参照のためのUUIDなどの一意の文字列識別子を提供します。
* **requirement**: ルールの特定の認可要件とメカニズムを定義するシリアライズされたデータを含みます。
* **comment**: ドキュメントと明確さのためにルールに関する人間が読める説明またはコメントを提供します。

### Example
```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>rule</string>
<key>comment</key>
<string>For modification of TCC settings.</string>
<key>created</key>
<real>701369782.01043606</real>
<key>modified</key>
<real>701369782.01043606</real>
<key>rule</key>
<array>
<string>authenticate-admin-nonshared</string>
</array>
<key>version</key>
<integer>0</integer>
</dict>
</plist>
```
さらに、[https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) では、`authenticate-admin-nonshared` の意味を見ることができます：
```json
{
'allow-root' : 'false',
'authenticate-user' : 'true',
'class' : 'user',
'comment' : 'Authenticate as an administrator.',
'group' : 'admin',
'session-owner' : 'false',
'shared' : 'false',
'timeout' : '30',
'tries' : '10000',
'version' : '1'
}
```
## Authd

これは、クライアントが機密のアクションを実行するための承認要求を受け取るデーモンです。`XPCServices/`フォルダー内に定義されたXPCサービスとして機能し、ログは`/var/log/authd.log`に書き込まれます。

さらに、セキュリティツールを使用すると、多くの`Security.framework` APIをテストすることが可能です。例えば、`AuthorizationExecuteWithPrivileges`を実行するには、次のようにします: `security execute-with-privileges /bin/ls`

これにより、`/usr/libexec/security_authtrampoline /bin/ls`がrootとしてフォークされ、lsをrootとして実行するための権限を求めるプロンプトが表示されます:

<figure><img src="../../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
