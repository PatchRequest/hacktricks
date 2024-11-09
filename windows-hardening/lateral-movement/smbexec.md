# SmbExec/ScExec

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

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**あなたのウェブアプリ、ネットワーク、クラウドに対するハッカーの視点を得る**

**実際のビジネスに影響を与える重大で悪用可能な脆弱性を見つけて報告します。** 20以上のカスタムツールを使用して攻撃面をマッピングし、特権を昇格させるセキュリティ問題を見つけ、自動化されたエクスプロイトを使用して重要な証拠を収集し、あなたの努力を説得力のある報告書に変えます。

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## 仕組み

**Smbexec**は、Windowsシステムでのリモートコマンド実行に使用されるツールで、**Psexec**に似ていますが、ターゲットシステムに悪意のあるファイルを置くことを避けます。

### **SMBExec**に関する重要なポイント

- ターゲットマシン上に一時的なサービス（例えば、「BTOBTO」）を作成してcmd.exe（%COMSPEC%）を介してコマンドを実行し、バイナリを落とさないように動作します。
- ステルスなアプローチにもかかわらず、実行された各コマンドのイベントログを生成し、非対話型の「シェル」の形式を提供します。
- **Smbexec**を使用して接続するためのコマンドは次のようになります:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### バイナリなしでコマンドを実行する

- **Smbexec** は、ターゲット上に物理的なバイナリを必要とせず、サービスの binPaths を通じて直接コマンドを実行することを可能にします。
- この方法は、Windows ターゲット上で一時的なコマンドを実行するのに便利です。たとえば、Metasploit の `web_delivery` モジュールと組み合わせることで、PowerShell 対象のリバース Meterpreter ペイロードを実行できます。
- 攻撃者のマシン上にリモートサービスを作成し、binPath を cmd.exe を通じて提供されたコマンドを実行するように設定することで、ペイロードを成功裏に実行し、サービス応答エラーが発生しても Metasploit リスナーでコールバックとペイロードの実行を達成することが可能です。

### コマンドの例

サービスを作成して開始するには、以下のコマンドを使用できます：
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
FOr further details check [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## References
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**あなたのウェブアプリ、ネットワーク、クラウドに対するハッカーの視点を得る**

**実際のビジネスに影響を与える重要で悪用可能な脆弱性を見つけて報告します。** 攻撃面をマッピングし、特権を昇格させるセキュリティ問題を見つけ、自動化されたエクスプロイトを使用して重要な証拠を収集し、あなたの努力を説得力のある報告書に変えるために、20以上のカスタムツールを使用してください。

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングのトリックを共有してください。**

</details>
{% endhint %}
