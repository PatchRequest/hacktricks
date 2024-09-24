# macOS Sandbox

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## 基本情報

MacOS Sandbox（最初はSeatbeltと呼ばれていた）は、**サンドボックス内で実行されるアプリケーション**を、アプリが実行されている**サンドボックスプロファイルで指定された許可されたアクション**に制限します。これにより、**アプリケーションが予期されるリソースのみをアクセスすることが保証されます**。

**`com.apple.security.app-sandbox`**の**権限**を持つアプリは、サンドボックス内で実行されます。**Appleのバイナリ**は通常サンドボックス内で実行され、**App Store**のすべてのアプリケーションはその権限を持っています。したがって、いくつかのアプリケーションはサンドボックス内で実行されます。

プロセスが何をできるか、またはできないかを制御するために、**サンドボックスはほぼすべての操作にフック**を持っています（ほとんどのシステムコールを含む）**MACF**を使用しています。ただし、アプリの**権限**に応じて、サンドボックスはプロセスに対してより許可的になる場合があります。

サンドボックスのいくつかの重要なコンポーネントは次のとおりです：

* **カーネル拡張** `/System/Library/Extensions/Sandbox.kext`
* **プライベートフレームワーク** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* ユーザーランドで実行される**デーモン** `/usr/libexec/sandboxd`
* **コンテナ** `~/Library/Containers`

### コンテナ

すべてのサンドボックス化されたアプリケーションは、`~/Library/Containers/{CFBundleIdentifier}`に独自のコンテナを持ちます：
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
各バンドルIDフォルダー内には、**plist**とアプリの**データディレクトリ**があり、ホームフォルダーを模した構造になっています：
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
{% hint style="danger" %}
注意してください。シンボリックリンクがSandboxから「脱出」して他のフォルダにアクセスするために存在していても、アプリはそれらにアクセスするための**権限を持っている必要があります**。これらの権限は、`RedirectablePaths`の**`.plist`**の中にあります。
{% endhint %}

**`SandboxProfileData`**は、B64にエスケープされたコンパイル済みのサンドボックスプロファイルCFDataです。
```bash
# Get container config
## You need FDA to access the file, not even just root can read it
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
{% hint style="warning" %}
Sandboxedアプリケーションによって作成/変更されたすべてのものには**隔離属性**が付与されます。これにより、サンドボックスアプリが**`open`**を使用して何かを実行しようとした場合に、Gatekeeperがトリガーされてサンドボックス空間が防止されます。
{% endhint %}

## サンドボックスプロファイル

サンドボックスプロファイルは、その**サンドボックス**で何が**許可/禁止**されるかを示す設定ファイルです。これは**サンドボックスプロファイル言語（SBPL）**を使用し、[**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\))プログラミング言語を利用しています。

ここに例があります：
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
{% hint style="success" %}
この[**研究**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)を確認して、許可または拒否される可能性のある他のアクションを確認してください。

プロファイルのコンパイルされたバージョンでは、操作の名前がdylibおよびkextによって知られている配列のエントリに置き換えられ、コンパイルされたバージョンが短く、読みづらくなります。
{% endhint %}

重要な**システムサービス**も、`mdnsresponder`サービスのように独自のカスタム**サンドボックス**内で実行されます。これらのカスタム**サンドボックスプロファイル**は以下で確認できます：

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**
* 他のサンドボックスプロファイルは[https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles)で確認できます。

**App Store**アプリは**プロファイル****`/System/Library/Sandbox/Profiles/application.sb`**を使用します。このプロファイルで、**`com.apple.security.network.server`**のような権限がプロセスにネットワークを使用することを許可する方法を確認できます。

SIPは、/System/Library/Sandbox/rootless.confにあるplatform\_profileというサンドボックスプロファイルです。

### サンドボックスプロファイルの例

特定のサンドボックスプロファイルでアプリケーションを起動するには、次のようにします：
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% tabs %}
{% tab title="touch" %}
{% code title="touch.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
{% endcode %}
```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```
{% code title="touch2.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```
{% endcode %}

{% code title="touch3.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="info" %}
**Appleが作成した** **ソフトウェア**は、**Windows**上で**追加のセキュリティ対策**（アプリケーションサンドボックスなど）を持っていないことに注意してください。
{% endhint %}

バイパスの例:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)（彼らは`~$`で始まる名前のファイルをサンドボックスの外に書き込むことができます）。

### サンドボックストレース

#### プロファイル経由

アクションがチェックされるたびにサンドボックスが実行するすべてのチェックをトレースすることが可能です。そのためには、次のプロファイルを作成します:

{% code title="trace.sb" %}
```scheme
(version 1)
(trace /tmp/trace.out)
```
{% endcode %}

その後、そのプロファイルを使用して何かを実行します:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
In `/tmp/trace.out` では、呼び出されるたびに実行される各サンドボックスチェックを見ることができます（つまり、多くの重複があります）。

**`-t`** パラメータを使用してサンドボックスをトレースすることも可能です: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### API経由

`libsystem_sandbox.dylib` にエクスポートされた関数 `sandbox_set_trace_path` は、サンドボックスチェックが書き込まれるトレースファイル名を指定することを可能にします。\
`sandbox_vtrace_enable()` を呼び出し、その後 `sandbox_vtrace_report()` を呼び出してバッファからログエラーを取得することも可能です。

### サンドボックス検査

`libsandbox.dylib` は、プロセスのサンドボックス状態のリスト（拡張を含む）を提供する `sandbox_inspect_pid` という関数をエクスポートしています。ただし、プラットフォームバイナリのみがこの関数を使用できます。

### MacOS & iOS サンドボックスプロファイル

MacOS は、システムサンドボックスプロファイルを **/usr/share/sandbox/** と **/System/Library/Sandbox/Profiles** の2つの場所に保存します。

サードパーティアプリケーションが _**com.apple.security.app-sandbox**_ 権限を持っている場合、システムはそのプロセスに **/System/Library/Sandbox/Profiles/application.sb** プロファイルを適用します。

iOS では、デフォルトプロファイルは **container** と呼ばれ、SBPL テキスト表現はありません。メモリ内では、このサンドボックスはサンドボックスからの各権限のための許可/拒否バイナリツリーとして表現されます。

### App Store アプリのカスタム SBPL

企業がアプリを **カスタムサンドボックスプロファイル** で実行することが可能です（デフォルトのものではなく）。彼らは **`com.apple.security.temporary-exception.sbpl`** 権限を使用する必要があり、これは Apple によって承認される必要があります。

この権限の定義は **`/System/Library/Sandbox/Profiles/application.sb:`** で確認できます。
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
This will **eval the string after this entitlement** as an Sandbox profile.

### Compiling & decompiling a Sandbox Profile

The **`sandbox-exec`** tool uses the functions `sandbox_compile_*` from `libsandbox.dylib`. The main functions exported are: `sandbox_compile_file` (expects a file path, param `-f`), `sandbox_compile_string` (expects a string, param `-p`), `sandbox_compile_name` (expects a name of a container, param `-n`), `sandbox_compile_entitlements` (expects entitlements plist).

This reversed and [**open sourced version of the tool sandbox-exec**](https://newosxbook.com/src.jl?tree=listings\&file=/sandbox\_exec.c) allows to make **`sandbox-exec`** write into a file the compiled sandbox profile.

Moreover, to confine a process inside a container it might call `sandbox_spawnattrs_set[container/profilename]` and pass a container or pre-existing profile.

## Debug & Bypass Sandbox

On macOS, unlike iOS where processes are sandboxed from the start by the kernel, **processes must opt-in to the sandbox themselves**. This means on macOS, a process is not restricted by the sandbox until it actively decides to enter it, although App Store apps are always sandboxed.

Processes are automatically Sandboxed from userland when they start if they have the entitlement: `com.apple.security.app-sandbox`. For a detailed explanation of this process check:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

## **Sandbox Extensions**

Extensions allow to give further privileges to an object and are giving calling one of the functions:

* `sandbox_issue_extension`
* `sandbox_extension_issue_file[_with_new_type]`
* `sandbox_extension_issue_mach`
* `sandbox_extension_issue_iokit_user_client_class`
* `sandbox_extension_issue_iokit_registry_rentry_class`
* `sandbox_extension_issue_generic`
* `sandbox_extension_issue_posix_ipc`

The extensions are stored in the second MACF label slot accessible from the process credentials. The following **`sbtool`** can access this information.

Note that extensions are usually granted by allowed processes, for example, `tccd` will grant the extension token of `com.apple.tcc.kTCCServicePhotos` when a process tried to access the photos and was allowed in a XPC message. Then, the process will need to consume the extension token so it gets added to it.\
Note that the extension tokens are long hexadecimals that encode the granted permissions. However they don't have the allowed PID hardcoded which means that any process with access to the token might be **consumed by multiple processes**.

Note that extensions are very related to entitlements also, so having certain entitlements might automatically grant certain extensions.

### **Check PID Privileges**

[**According to this**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), the **`sandbox_check`** functions (it's a `__mac_syscall`), can check **if an operation is allowed or not** by the sandbox in a certain PID, audit token or unique ID.

The [**tool sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) (find it [compiled here](https://newosxbook.com/articles/hitsb.html)) can check if a PID can perform a certain actions:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

サンドボックスを一時停止および再開することも可能で、`libsystem_sandbox.dylib`の`sandbox_suspend`および`sandbox_unsuspend`関数を使用します。

一時停止関数を呼び出すには、以下のようにいくつかの権限がチェックされ、呼び出し元が呼び出すことを許可されます：

* com.apple.private.security.sandbox-manager
* com.apple.security.print
* com.apple.security.temporary-exception.audio-unit-host

## mac\_syscall

このシステムコール（#381）は、最初の引数としてモジュールを示す文字列を期待し、次の引数には実行する関数を示すコードを指定します。3番目の引数は実行される関数に依存します。

関数`___sandbox_ms`呼び出しは、最初の引数に`"Sandbox"`を指定して`mac_syscall`をラップし、`___sandbox_msp`は`mac_set_proc`（#387）のラッパーです。次に、`___sandbox_ms`によってサポートされているコードの一部は、次の表に示されています：

* **set\_profile (#0)**: プロセスにコンパイル済みまたは名前付きプロファイルを適用します。
* **platform\_policy (#1)**: プラットフォーム固有のポリシーチェックを強制します（macOSとiOSで異なります）。
* **check\_sandbox (#2)**: 特定のサンドボックス操作の手動チェックを実行します。
* **note (#3)**: サンドボックスに注釈を追加します。
* **container (#4)**: 通常はデバッグまたは識別のために、サンドボックスに注釈を添付します。
* **extension\_issue (#5)**: プロセスの新しい拡張を生成します。
* **extension\_consume (#6)**: 指定された拡張を消費します。
* **extension\_release (#7)**: 消費された拡張に関連付けられたメモリを解放します。
* **extension\_update\_file (#8)**: サンドボックス内の既存のファイル拡張のパラメータを変更します。
* **extension\_twiddle (#9)**: 既存のファイル拡張を調整または変更します（例：TextEdit、rtf、rtfd）。
* **suspend (#10)**: すべてのサンドボックスチェックを一時的に停止します（適切な権限が必要です）。
* **unsuspend (#11)**: 以前に一時停止されたすべてのサンドボックスチェックを再開します。
* **passthrough\_access (#12)**: サンドボックスチェックをバイパスしてリソースへの直接パススルーアクセスを許可します。
* **set\_container\_path (#13)**: （iOSのみ）アプリグループまたは署名IDのためのコンテナパスを設定します。
* **container\_map (#14)**: （iOSのみ）`containermanagerd`からコンテナパスを取得します。
* **sandbox\_user\_state\_item\_buffer\_send (#15)**: （iOS 10+）サンドボックス内のユーザーモードメタデータを設定します。
* **inspect (#16)**: サンドボックス化されたプロセスに関するデバッグ情報を提供します。
* **dump (#18)**: （macOS 11）分析のためにサンドボックスの現在のプロファイルをダンプします。
* **vtrace (#19)**: 監視またはデバッグのためにサンドボックス操作をトレースします。
* **builtin\_profile\_deactivate (#20)**: （macOS < 11）名前付きプロファイルを無効にします（例：`pe_i_can_has_debugger`）。
* **check\_bulk (#21)**: 単一の呼び出しで複数の`sandbox_check`操作を実行します。
* **reference\_retain\_by\_audit\_token (#28)**: サンドボックスチェックで使用するための監査トークンの参照を作成します。
* **reference\_release (#29)**: 以前に保持された監査トークン参照を解放します。
* **rootless\_allows\_task\_for\_pid (#30)**: `task_for_pid`が許可されているかどうかを確認します（`csr`チェックに似ています）。
* **rootless\_whitelist\_push (#31)**: （macOS）システム整合性保護（SIP）マニフェストファイルを適用します。
* **rootless\_whitelist\_check (preflight) (#32)**: 実行前にSIPマニフェストファイルをチェックします。
* **rootless\_protected\_volume (#33)**: （macOS）ディスクまたはパーティションにSIP保護を適用します。
* **rootless\_mkdir\_protected (#34)**: ディレクトリ作成プロセスにSIP/DataVault保護を適用します。

## Sandbox.kext

iOSでは、カーネル拡張が`__TEXT.__const`セグメント内に**すべてのプロファイルをハードコーディング**しているため、変更されるのを防ぎます。以下はカーネル拡張からのいくつかの興味深い関数です：

* **`hook_policy_init`**: `mpo_policy_init`をフックし、`mac_policy_register`の後に呼び出されます。サンドボックスの初期化のほとんどを実行します。また、SIPも初期化します。
* **`hook_policy_initbsd`**: `security.mac.sandbox.sentinel`、`security.mac.sandbox.audio_active`、および`security.mac.sandbox.debug_mode`を登録するsysctlインターフェースを設定します（`PE_i_can_has_debugger`でブートされた場合）。
* **`hook_policy_syscall`**: "Sandbox"を最初の引数として、操作を示すコードを2番目の引数として`mac_syscall`によって呼び出されます。スイッチを使用して、要求されたコードに応じて実行するコードを見つけます。

### MACF Hooks

**`Sandbox.kext`**は、MACFを介して100以上のフックを使用します。ほとんどのフックは、アクションを実行することを許可する些細なケースをチェックするだけで、そうでない場合は、**`cred_sb_evalutate`**を呼び出し、**資格情報**と**操作**に対応する番号、そして**出力**用の**バッファ**を渡します。

その良い例は、**`_mpo_file_check_mmap`**関数で、これは**`mmap`**をフックし、新しいメモリが書き込み可能かどうかをチェックし（そうでない場合は実行を許可）、次にそれがdyld共有キャッシュに使用されているかどうかをチェックし、そうであれば実行を許可し、最後に**`cred_sb_evalutate`**を呼び出してさらなる許可チェックを実行します。

さらに、サンドボックスが使用する数百のフックの中で、特に興味深い3つがあります：

* `mpo_proc_check_for`: 必要に応じてプロファイルを適用し、以前に適用されていなかった場合。
* `mpo_vnode_check_exec`: プロセスが関連するバイナリをロードするときに呼び出され、プロファイルチェックが実行され、SUID/SGID実行を禁止するチェックも行われます。
* `mpo_cred_label_update_execve`: ラベルが割り当てられるときに呼び出されます。これは、バイナリが完全にロードされるがまだ実行されていないときに呼び出されるため、最も長いものです。サンドボックスオブジェクトの作成、kauth資格情報へのサンドボックス構造の添付、machポートへのアクセスの削除などのアクションを実行します。

**`cred_sb_evalutate`**は**`sb_evaluate`**のラッパーであり、この関数は渡された資格情報を取得し、次に**`eval`**関数を使用して評価を実行します。通常、これはすべてのプロセスにデフォルトで適用される**プラットフォームプロファイル**を評価し、その後**特定のプロセスプロファイル**を評価します。プラットフォームプロファイルは、macOSの**SIP**の主要なコンポーネントの1つです。

## Sandboxd

サンドボックスには、XPC Machサービス`com.apple.sandboxd`を公開し、カーネル拡張が通信に使用する特別なポート14（`HOST_SEATBELT_PORT`）をバインドするユーザーデーモンもあります。MIGを使用していくつかの関数を公開します。

## References

* [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
