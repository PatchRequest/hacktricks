# macOS SIP

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

## **基本情報**

**System Integrity Protection (SIP)** は、macOSにおいて、最も特権のあるユーザーでさえも重要なシステムフォルダーに対して不正な変更を行うことを防ぐために設計されたメカニズムです。この機能は、保護された領域内のファイルを追加、変更、または削除する行動を制限することによって、システムの整合性を維持する上で重要な役割を果たします。SIPによって保護されている主なフォルダーは以下の通りです：

* **/System**
* **/bin**
* **/sbin**
* **/usr**

SIPの動作を規定するルールは、**`/System/Library/Sandbox/rootless.conf`** にある設定ファイルで定義されています。このファイル内では、アスタリスク（\*）で始まるパスは、厳格なSIP制限の例外として示されています。

以下の例を考えてみてください：
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
このスニペットは、SIPが一般的に**`/usr`**ディレクトリを保護している一方で、特定のサブディレクトリ（`/usr/libexec/cups`、`/usr/local`、および`/usr/share/man`）では修正が許可されていることを示しています。これは、それらのパスの前にアスタリスク（\*）があることによって示されています。

ディレクトリまたはファイルがSIPによって保護されているかどうかを確認するには、**`ls -lOd`**コマンドを使用して**`restricted`**または**`sunlnk`**フラグの存在を確認できます。例えば：
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
この場合、**`sunlnk`** フラグは `/usr/libexec/cups` ディレクトリ自体が **削除できない** ことを示していますが、その中のファイルは作成、変更、または削除できます。

一方:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
ここで、**`restricted`** フラグは、`/usr/libexec` ディレクトリが SIP によって保護されていることを示します。SIP によって保護されたディレクトリでは、ファイルを作成、変更、または削除することはできません。

さらに、ファイルが **`com.apple.rootless`** 拡張 **属性** を含む場合、そのファイルも **SIP によって保護されます**。

{% hint style="success" %}
**Sandbox** フック **`hook_vnode_check_setextattr`** は、拡張属性 **`com.apple.rootless`** を変更しようとする試みを防ぎます。
{% endhint %}

**SIP は他のルートアクションも制限します** 例えば：

* 信頼できないカーネル拡張の読み込み
* Apple 署名プロセスのタスクポートの取得
* NVRAM 変数の変更
* カーネルデバッグの許可

オプションは、ビットフラグとして nvram 変数に保持されます（Intel では `csr-active-config`、ARM ではブートされたデバイステーブルから `lp-sip0` が読み取られます）。フラグは `csr.sh` の XNU ソースコードで見つけることができます：

<figure><img src="../../../.gitbook/assets/image (1192).png" alt=""><figcaption></figcaption></figure>

### SIP ステータス

次のコマンドを使用して、システムで SIP が有効かどうかを確認できます：
```bash
csrutil status
```
SIPを無効にする必要がある場合は、リカバリーモードでコンピュータを再起動する必要があります（起動中にCommand+Rを押します）。次に、以下のコマンドを実行します：
```bash
csrutil disable
```
SIPを有効のままにしてデバッグ保護を削除したい場合は、次のコマンドを使用できます:
```bash
csrutil enable --without debug
```
### Other Restrictions

* **署名されていないカーネル拡張の読み込みを禁止** (kexts) し、検証された拡張のみがシステムカーネルと相互作用することを保証します。
* **macOSシステムプロセスのデバッグを防止**し、コアシステムコンポーネントを不正アクセスや変更から保護します。
* **dtraceのようなツールを抑制**し、システムの動作の完全性をさらに保護します。

[**このトークでSIP情報についてもっと学ぶ**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

### **SIP関連の権限**

* `com.apple.rootless.xpc.bootstrap`: launchdを制御
* `com.apple.rootless.install[.heritable]`: ファイルシステムにアクセス
* `com.apple.rootless.kext-management`: `kext_request`
* `com.apple.rootless.datavault.controller`: UF\_DATAVAULTを管理
* `com.apple.rootless.xpc.bootstrap`: XPCセットアップ機能
* `com.apple.rootless.xpc.effective-root`: launchd XPC経由でのルート
* `com.apple.rootless.restricted-block-devices`: 生のブロックデバイスへのアクセス
* `com.apple.rootless.internal.installer-equivalent`: 制限のないファイルシステムアクセス
* `com.apple.rootless.restricted-nvram-variables[.heritable]`: NVRAMへの完全アクセス
* `com.apple.rootless.storage.label`: 対応するラベルを持つcom.apple.rootless xattrによって制限されたファイルを変更
* `com.apple.rootless.volume.VM.label`: ボリューム上のVMスワップを維持

## SIP Bypasses

SIPをバイパスすることで攻撃者は以下を行うことができます：

* **ユーザーデータにアクセス**: すべてのユーザーアカウントからメール、メッセージ、Safariの履歴などの機密ユーザーデータを読み取る。
* **TCCバイパス**: TCC (Transparency, Consent, and Control) データベースを直接操作し、ウェブカメラ、マイク、その他のリソースへの不正アクセスを許可。
* **持続性を確立**: SIP保護された場所にマルウェアを配置し、ルート権限による削除に対して抵抗力を持たせる。これには、マルウェア除去ツール (MRT) の改ざんの可能性も含まれます。
* **カーネル拡張を読み込む**: 追加の保護があるにもかかわらず、SIPをバイパスすることで署名されていないカーネル拡張の読み込みが簡素化されます。

### インストーラーパッケージ

**Appleの証明書で署名されたインストーラーパッケージ**は、その保護をバイパスできます。これは、標準の開発者によって署名されたパッケージであっても、SIP保護されたディレクトリを変更しようとするとブロックされることを意味します。

### 存在しないSIPファイル

1つの潜在的な抜け穴は、**`rootless.conf`にファイルが指定されているが現在存在しない場合**、それを作成できることです。マルウェアはこれを利用して**システム上で持続性を確立**する可能性があります。たとえば、悪意のあるプログラムは、`rootless.conf`にリストされているが存在しない場合、`/System/Library/LaunchDaemons`に.plistファイルを作成することができます。

### com.apple.rootless.install.heritable

{% hint style="danger" %}
権限 **`com.apple.rootless.install.heritable`** はSIPをバイパスすることを許可します
{% endhint %}

#### [CVE-2019-8561](https://objective-see.org/blog/blog\_0x42.html) <a href="#cve" id="cve"></a>

システムがそのコード署名を検証した後に**インストーラーパッケージを入れ替える**ことが可能であることが発見されました。その後、システムは元の代わりに悪意のあるパッケージをインストールします。これらのアクションは**`system_installd`**によって実行されるため、SIPをバイパスすることができます。

#### [CVE-2020–9854](https://objective-see.org/blog/blog\_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

マウントされたイメージまたは外部ドライブからパッケージがインストールされた場合、**インストーラー**は**そのファイルシステム**からバイナリを**実行**します（SIP保護された場所からではなく）、これにより**`system_installd`**が任意のバイナリを実行します。

#### CVE-2021-30892 - Shrootless

[**このブログ投稿の研究者たち**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)は、macOSのシステム整合性保護 (SIP) メカニズムに「Shrootless」と呼ばれる脆弱性を発見しました。この脆弱性は、**`system_installd`**デーモンに関連しており、**`com.apple.rootless.install.heritable`**という権限を持ち、その子プロセスがSIPのファイルシステム制限をバイパスできるようにします。

**`system_installd`**デーモンは、**Apple**によって署名されたパッケージをインストールします。

研究者たちは、Apple署名のパッケージ (.pkgファイル) のインストール中に、**`system_installd`**がパッケージに含まれる**post-install**スクリプトを**実行**することを発見しました。これらのスクリプトはデフォルトシェルである**`zsh`**によって実行され、存在する場合は非対話モードでも**`/etc/zshenv`**ファイルからコマンドが自動的に**実行**されます。この動作は攻撃者によって悪用される可能性があります：悪意のある`/etc/zshenv`ファイルを作成し、**`system_installd`が`zsh`を呼び出すのを待つ**ことで、デバイス上で任意の操作を実行できます。

さらに、**`/etc/zshenv`は一般的な攻撃手法として使用できることが発見されました**。各ユーザープロファイルには`~/.zshenv`ファイルがあり、これは`/etc/zshenv`と同様に動作しますが、ルート権限は必要ありません。このファイルは持続性メカニズムとして使用され、`zsh`が起動するたびにトリガーされるか、特権昇格メカニズムとして使用される可能性があります。管理者ユーザーが`sudo -s`または`sudo <command>`を使用してルートに昇格すると、`~/.zshenv`ファイルがトリガーされ、実質的にルートに昇格します。

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

[**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)では、同じ**`system_installd`**プロセスが悪用される可能性があることが発見されました。なぜなら、**`/tmp`内のSIPによって保護されたランダムに名前が付けられたフォルダー内に**post-installスクリプトを配置していたからです。**`/tmp`自体はSIPによって保護されていないため、**仮想イメージをマウント**し、その後**インストーラー**が**post-installスクリプト**をそこに配置し、**仮想イメージをアンマウント**し、すべての**フォルダーを再作成**し、**ペイロード**を実行する**post installation**スクリプトを追加することが可能でした。

#### [fsck\_csユーティリティ](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

**`fsck_cs`**が重要なファイルを破損させるように誤解される脆弱性が特定されました。これは、**シンボリックリンク**をたどる能力によるものでした。具体的には、攻撃者は`/dev/diskX`から`/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`へのリンクを作成しました。**`fsck_cs`**を`/dev/diskX`で実行すると、`Info.plist`が破損しました。このファイルの整合性は、カーネル拡張の読み込みを制御するオペレーティングシステムのSIP (System Integrity Protection) にとって重要です。一度破損すると、SIPのカーネル除外を管理する能力が損なわれます。

この脆弱性を悪用するためのコマンドは：
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
この脆弱性の悪用は深刻な影響を及ぼします。通常、カーネル拡張の権限を管理する役割を持つ `Info.plist` ファイルは無効になります。これには、`AppleHWAccess.kext` のような特定の拡張をブラックリストに登録できないことが含まれます。その結果、SIPの制御メカニズムが機能しなくなるため、この拡張が読み込み可能になり、システムのRAMへの不正な読み書きアクセスが許可されます。

#### [SIP保護フォルダ上にマウント](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

**保護を回避するためにSIP保護フォルダ上に新しいファイルシステムをマウントする**ことが可能でした。
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [アップグレーダーバイパス (2016)](https://objective-see.org/blog/blog\_0x14.html)

システムは、OSをアップグレードするために`Install macOS Sierra.app`内の埋め込まれたインストーラーディスクイメージからブートするように設定されており、`bless`ユーティリティを利用しています。使用されるコマンドは次のとおりです:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
このプロセスのセキュリティは、攻撃者がブート前にアップグレードイメージ（`InstallESD.dmg`）を変更すると危険にさらされる可能性があります。この戦略は、動的ローダー（dyld）を悪意のあるバージョン（`libBaseIA.dylib`）に置き換えることを含みます。この置き換えにより、インストーラーが開始されると攻撃者のコードが実行されます。

攻撃者のコードはアップグレードプロセス中に制御を取得し、インストーラーに対するシステムの信頼を悪用します。攻撃は、`InstallESD.dmg`イメージをメソッドスウィズリングを通じて変更することによって進行し、特に`extractBootBits`メソッドをターゲットにします。これにより、ディスクイメージが使用される前に悪意のあるコードを注入することが可能になります。

さらに、`InstallESD.dmg`内には、アップグレードコードのルートファイルシステムとして機能する`BaseSystem.dmg`があります。ここに動的ライブラリを注入することで、悪意のあるコードはOSレベルのファイルを変更できるプロセス内で動作することができ、システムの危険性が大幅に増加します。

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

この[**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk)の講演では、**`systemmigrationd`**（SIPをバイパスできる）が**bash**および**perl**スクリプトを実行し、環境変数**`BASH_ENV`**および**`PERL5OPT`**を介して悪用される可能性があることが示されています。

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

[**このブログ記事で詳述されているように**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)、`InstallAssistant.pkg`パッケージの`postinstall`スクリプトが実行されていました：
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
and it was possible to crate a symlink in `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` that would allow a user to **unrestrict any file, bypassing SIP protection**.

### **com.apple.rootless.install**

{% hint style="danger" %}
権限 **`com.apple.rootless.install`** は SIP をバイパスすることを許可します
{% endhint %}

権限 `com.apple.rootless.install` は、macOS のシステム整合性保護 (SIP) をバイパスすることが知られています。これは特に [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) に関連して言及されました。

この特定のケースでは、`/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` にあるシステム XPC サービスがこの権限を持っています。これにより、関連するプロセスは SIP 制約を回避できます。さらに、このサービスは、セキュリティ対策を強制せずにファイルを移動することを許可する方法を提供します。

## シールされたシステムスナップショット

シールされたシステムスナップショットは、Apple が **macOS Big Sur (macOS 11)** で導入した機能で、**システム整合性保護 (SIP)** メカニズムの一部として、追加のセキュリティとシステムの安定性を提供します。これらは本質的にシステムボリュームの読み取り専用バージョンです。

以下は、より詳細な説明です：

1. **不変のシステム**: シールされたシステムスナップショットは、macOS システムボリュームを「不変」にし、変更できないようにします。これにより、セキュリティやシステムの安定性を損なう可能性のある不正または偶発的な変更を防ぎます。
2. **システムソフトウェアの更新**: macOS の更新やアップグレードをインストールすると、macOS は新しいシステムスナップショットを作成します。macOS の起動ボリュームは、その後 **APFS (Apple File System)** を使用してこの新しいスナップショットに切り替えます。更新を適用するプロセス全体が安全で信頼性が高くなり、更新中に何か問題が発生した場合でも、システムは常に前のスナップショットに戻ることができます。
3. **データの分離**: macOS Catalina で導入されたデータとシステムボリュームの分離の概念と組み合わせて、シールされたシステムスナップショット機能は、すべてのデータと設定が別の「**データ**」ボリュームに保存されることを保証します。この分離により、データはシステムから独立し、システムの更新プロセスが簡素化され、システムのセキュリティが向上します。

これらのスナップショットは macOS によって自動的に管理され、APFS のスペース共有機能のおかげでディスク上に追加のスペースを占有しません。また、これらのスナップショットは、ユーザーがアクセス可能なシステム全体のバックアップである **Time Machine スナップショット** とは異なることに注意することも重要です。

### スナップショットの確認

コマンド **`diskutil apfs list`** は **APFS ボリュームの詳細** とそのレイアウトをリストします：

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-&#x3C; Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

前の出力では、**ユーザーがアクセス可能な場所** が `/System/Volumes/Data` にマウントされていることがわかります。

さらに、**macOS システムボリュームスナップショット** は `/` にマウントされており、**シールされています**（OS によって暗号的に署名されています）。したがって、SIP がバイパスされて変更されると、**OS はもう起動しません**。

また、シールが有効であることを確認することも可能です：
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
さらに、スナップショットディスクは**読み取り専用**としてマウントされます：
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
