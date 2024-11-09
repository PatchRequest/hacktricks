# PsExec/Winexec/ScExec

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## どのように機能するか

プロセスは以下のステップで概説されており、サービスバイナリがどのように操作され、SMBを介してターゲットマシンでリモート実行を達成するかを示しています：

1. **ADMIN$共有にサービスバイナリをSMB経由でコピー**します。
2. **リモートマシン上にサービスを作成**し、バイナリを指します。
3. サービスが**リモートで開始**されます。
4. 終了時に、サービスは**停止され、バイナリは削除**されます。

### **PsExecを手動で実行するプロセス**

msfvenomで作成され、ウイルス対策検出を回避するためにVeilを使用して難読化された実行可能ペイロード「met8888.exe」があると仮定します。これはmeterpreter reverse_httpペイロードを表します。以下のステップが取られます：

* **バイナリのコピー**：実行可能ファイルはコマンドプロンプトからADMIN$共有にコピーされますが、ファイルシステムのどこにでも配置して隠すことができます。
* **サービスの作成**：Windowsの`sc`コマンドを使用して、リモートでWindowsサービスを照会、作成、削除することができ、「meterpreter」という名前のサービスがアップロードされたバイナリを指すように作成されます。
* **サービスの開始**：最終ステップはサービスを開始することで、バイナリが本物のサービスバイナリでないため、期待される応答コードを返さず「タイムアウト」エラーが発生する可能性があります。このエラーは、主な目的がバイナリの実行であるため、重要ではありません。

Metasploitリスナーを観察すると、セッションが正常に開始されたことがわかります。

[scコマンドの詳細を学ぶ](https://technet.microsoft.com/en-us/library/bb490995.aspx)。

詳細な手順については、[https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)を参照してください。

**Windows SysinternalsバイナリPsExec.exeを使用することもできます：**

![](<../../.gitbook/assets/image (928).png>)

[**SharpLateral**](https://github.com/mertdas/SharpLateral)を使用することもできます：

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
AWSハッキングを学び、練習する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、練習する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
