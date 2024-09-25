# macOS Security Protections

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

## Gatekeeper

Gatekeeperは通常、**Quarantine + Gatekeeper + XProtect**の組み合わせを指し、これはmacOSの3つのセキュリティモジュールで、**ユーザーがダウンロードした潜在的に悪意のあるソフトウェアを実行するのを防ごうとします**。

More information in:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Processes Limitants

### MACF



### SIP - System Integrity Protection

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

MacOS Sandboxは、サンドボックス内で実行されるアプリケーションの**許可されたアクションをサンドボックスプロファイルで指定されたものに制限します**。これにより、**アプリケーションが予期されるリソースのみをアクセスすることが保証されます**。

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)**はセキュリティフレームワークです。これは、アプリケーションの**権限を管理する**ために設計されており、特に機密機能へのアクセスを規制します。これには、**位置情報サービス、連絡先、写真、マイク、カメラ、アクセシビリティ、フルディスクアクセス**などの要素が含まれます。TCCは、アプリが明示的なユーザーの同意を得た後にのみこれらの機能にアクセスできるようにし、プライバシーと個人データの制御を強化します。

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Launch/Environment Constraints & Trust Cache

macOSの起動制約は、**プロセスの開始を規制する**ためのセキュリティ機能で、**誰が**プロセスを起動できるか、**どのように**、**どこから**起動するかを定義します。macOS Venturaで導入され、システムバイナリを制約カテゴリに分類し、**信頼キャッシュ**内に格納します。すべての実行可能バイナリには、**自己**、**親**、および**責任**制約を含む**起動**のための**ルール**が設定されています。macOS Sonomaでは、これらの機能が**環境**制約としてサードパーティアプリに拡張され、プロセスの起動条件を管理することで潜在的なシステムの悪用を軽減します。

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Malware Removal Tool

マルウェア除去ツール（MRT）は、macOSのセキュリティインフラの一部です。名前が示すように、MRTの主な機能は**感染したシステムから既知のマルウェアを削除することです**。

マルウェアがMacで検出されると（XProtectまたは他の手段によって）、MRTを使用して自動的に**マルウェアを削除**できます。MRTはバックグラウンドで静かに動作し、通常はシステムが更新されるときや新しいマルウェア定義がダウンロードされるときに実行されます（MRTがマルウェアを検出するためのルールはバイナリ内にあるようです）。

XProtectとMRTはどちらもmacOSのセキュリティ対策の一部ですが、異なる機能を果たします：

* **XProtect**は予防的なツールです。これは、**ファイルがダウンロードされるときにチェック**し、既知のマルウェアのタイプが検出されると、**ファイルのオープンを防ぎ**、マルウェアが最初からシステムに感染するのを防ぎます。
* **MRT**は、逆に、**反応的なツール**です。これは、システムでマルウェアが検出された後に動作し、問題のあるソフトウェアを削除してシステムをクリーンにすることを目的としています。

MRTアプリケーションは**`/Library/Apple/System/Library/CoreServices/MRT.app`**にあります。

## Background Tasks Management

**macOS**は、ツールが**コード実行を持続させるためのよく知られた技術を使用する**たびに**警告**を出すようになりました（ログイン項目、デーモンなど）、これによりユーザーは**どのソフトウェアが持続しているかをよりよく知ることができます**。

<figure><img src="../../../.gitbook/assets/image (1183).png" alt=""><figcaption></figcaption></figure>

これは、`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd`にある**デーモン**と、`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`にある**エージェント**によって実行されます。

**`backgroundtaskmanagementd`**が何かが持続的なフォルダにインストールされていることを知る方法は、**FSEventsを取得し**、それらのための**ハンドラ**を作成することです。

さらに、Appleによって維持される**よく知られたアプリケーション**を含むplistファイルがあり、これは`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`にあります。
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Enumeration

AppleのCLIツールを使用して、構成されたすべてのバックグラウンドアイテムを**列挙**することができます:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
さらに、この情報を[**DumpBTM**](https://github.com/objective-see/DumpBTM)を使ってリストすることも可能です。
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
この情報は**`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`**に保存されており、TerminalはFDAを必要とします。

### BTMの操作

新しい永続性が見つかると、**`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**というタイプのイベントが発生します。したがって、この**イベント**が送信されるのを**防ぐ**方法や、**エージェントがユーザーに警告するのを防ぐ**方法は、攻撃者がBTMを_**回避**_するのに役立ちます。

* **データベースのリセット**: 次のコマンドを実行すると、データベースがリセットされます（最初から再構築する必要があります）。ただし、何らかの理由で、これを実行した後は、**システムが再起動されるまで新しい永続性は警告されません**。
* **root**が必要です。
```bash
# Reset the database
sfltool resettbtm
```
* **エージェントを停止する**: 新しい検出が見つかったときに**ユーザーに警告しない**ように、エージェントに停止信号を送ることが可能です。
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
* **バグ**: **持続性を作成したプロセスがそれのすぐ後に存在する場合**、デーモンはそれについて**情報を取得しようとし**、**失敗し**、新しいものが持続していることを示すイベントを**送信できなくなります**。

参照および**BTMに関する詳細情報**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{% hint style="success" %}
AWSハッキングを学び、練習する:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、練習する: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* [**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。

</details>
{% endhint %}
